```diff
diff --git a/Android.bp b/Android.bp
index 3ac8129..b26648c 100644
--- a/Android.bp
+++ b/Android.bp
@@ -19,12 +19,8 @@ android_app {
         "src/**/I*.aidl",
         ":statslog-Iwlan-java-gen",
     ],
-    resource_dirs: [
-        "res",
-    ],
     static_libs: [
         "android-support-annotations",
-        "net-utils-dnspacket-common",
         "iwlan_telephony_flags_lib",
     ],
 
@@ -33,14 +29,28 @@ android_app {
         "androidx.annotation_annotation",
         "auto_value_annotations",
         "framework-annotations-lib",
-        "framework-connectivity",
-        "framework-wifi",
         "modules-utils-handlerexecutor",
     ],
 
+    errorprone: {
+        enabled: true,
+        // Error-prone checking only warns of problems when building. To make the build fail with
+        // these errors, list the specific error-prone problems below.
+        javacflags: [
+            "-Xep:NullablePrimitive:ERROR",
+            "-Xep:AutoValueImmutableFields:OFF",
+            "-Xep:DoNotMockAutoValue:OFF",
+            "-Xep:JavaUtilDate:OFF",
+            "-Xep:LongFloatConversion:OFF",
+        ],
+    },
+
     plugins: ["auto_value_plugin"],
 
-    required: ["privapp-permlist_com.google.android.iwlan.xml"],
+    required: [
+        "privapp-permlist_com.google.android.iwlan.xml",
+        "sysconfig_com.google.android.iwlan.xml",
+    ],
 
     owner: "google",
     system_ext_specific: true,
@@ -52,7 +62,15 @@ android_app {
 prebuilt_etc {
     name: "privapp-permlist_com.google.android.iwlan.xml",
     sub_dir: "permissions",
-    src: "com.google.android.iwlan.xml",
+    src: "privapp-permlist_com.google.android.iwlan.xml",
+    filename_from_src: true,
+    system_ext_specific: true,
+}
+
+prebuilt_etc {
+    name: "sysconfig_com.google.android.iwlan.xml",
+    sub_dir: "sysconfig",
+    src: "sysconfig_com.google.android.iwlan.xml",
     filename_from_src: true,
     system_ext_specific: true,
 }
@@ -81,6 +99,19 @@ android_test {
         "auto_value_annotations",
     ],
 
+    errorprone: {
+        enabled: true,
+        // Error-prone checking only warns of problems when building. To make the build fail with
+        // these errors, list the specific error-prone problems below.
+        javacflags: [
+            "-Xep:NullablePrimitive:ERROR",
+            "-Xep:AutoValueImmutableFields:OFF",
+            "-Xep:DoNotMockAutoValue:OFF",
+            "-Xep:JavaUtilDate:OFF",
+            "-Xep:LongFloatConversion:OFF",
+        ],
+    },
+
     plugins: ["auto_value_plugin"],
 
     static_libs: [
@@ -89,7 +120,6 @@ android_test {
         "frameworks-base-testutils",
         "mockito-target-inline-minus-junit4",
         "mockito-target-extended-minus-junit4",
-        "net-utils-dnspacket-common",
         "iwlan_telephony_flags_lib",
         "platform-test-annotations",
         "flag-junit",
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index bfa0fdf..5f44f46 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -35,12 +35,6 @@
               <action android:name="android.telephony.NetworkService" />
           </intent-filter>
       </service>
-    <receiver android:name=".IwlanBroadcastReceiver"
-              android:exported="true">
-         <intent-filter>
-            <action android:name="android.telephony.action.CARRIER_SIGNAL_PCO_VALUE"/>
-         </intent-filter>
-    </receiver>
       <uses-library android:name="android.net.ipsec.ike" />
   </application>
 </manifest>
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index fdcae9c..30701ae 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -2,5 +2,4 @@
 google_java_format = true
 
 [Hook Scripts]
-checkstyle_hook = ${REPO_ROOT}/prebuilts/checkstyle/checkstyle.py --sha ${PREUPLOAD_COMMIT}
 hidden_api_txt_checksorted_hook = ${REPO_ROOT}/tools/platform-compat/hiddenapi/checksorted_sha.sh ${PREUPLOAD_COMMIT} ${REPO_ROOT}
diff --git a/flags/main.aconfig b/flags/main.aconfig
index 2e5f40c..c9a38b6 100644
--- a/flags/main.aconfig
+++ b/flags/main.aconfig
@@ -43,3 +43,9 @@ flag {
     description: "Allow additional ePDG selections for emergency PDN"
     bug: "244670857"
 }
+flag {
+    name: "validate_underlying_network_on_no_response"
+    namespace: "iwlan_telephony"
+    description: "Trigger underlying network validation check upon no network response"
+    bug: "274863262"
+}
diff --git a/com.google.android.iwlan.xml b/privapp-permlist_com.google.android.iwlan.xml
similarity index 100%
rename from com.google.android.iwlan.xml
rename to privapp-permlist_com.google.android.iwlan.xml
diff --git a/res/.gitignore b/res/.gitignore
deleted file mode 100644
index 8d1c8b6..0000000
--- a/res/.gitignore
+++ /dev/null
@@ -1 +0,0 @@
- 
diff --git a/src/com/google/android/iwlan/ErrorPolicyManager.java b/src/com/google/android/iwlan/ErrorPolicyManager.java
index 6cd0c99..e3eeb8f 100644
--- a/src/com/google/android/iwlan/ErrorPolicyManager.java
+++ b/src/com/google/android/iwlan/ErrorPolicyManager.java
@@ -171,8 +171,8 @@ public class ErrorPolicyManager {
     /**
      * Returns ErrorPolicyManager instance for the subId
      *
-     * @param context
-     * @param slotId
+     * @param context the context to be used by the ErrorPolicyManager
+     * @param slotId the slot ID for which the ErrorPolicyManager instance is required
      */
     public static ErrorPolicyManager getInstance(@NonNull Context context, int slotId) {
         return mInstances.computeIfAbsent(slotId, k -> new ErrorPolicyManager(context, slotId));
@@ -183,9 +183,7 @@ public class ErrorPolicyManager {
         mInstances.clear();
     }
 
-    /**
-     * Release or reset the instance.
-     */
+    /** Release or reset the instance. */
     public void releaseInstance() {
         Log.d(LOG_TAG, "Release Instance with slotId: " + mSlotId);
         IwlanEventListener.getInstance(mContext, mSlotId).removeEventListener(mHandler);
@@ -283,33 +281,29 @@ public class ErrorPolicyManager {
     }
 
     private int getDataFailCause(IwlanError error) {
-        int ret;
         int errorType = error.getErrorType();
-        switch (errorType) {
-            case IwlanError.NO_ERROR -> ret = DataFailCause.NONE;
+        return switch (errorType) {
+            case IwlanError.NO_ERROR -> DataFailCause.NONE;
             case IwlanError.IKE_PROTOCOL_EXCEPTION ->
-                    ret = getDataFailCauseForIkeProtocolException(error.getException());
-            case IwlanError.IKE_INTERNAL_IO_EXCEPTION ->
-                    ret = DataFailCause.IWLAN_IKEV2_MSG_TIMEOUT;
-            case IwlanError.IKE_GENERIC_EXCEPTION -> ret = DataFailCause.ERROR_UNSPECIFIED;
+                    getDataFailCauseForIkeProtocolException(error.getException());
+            case IwlanError.IKE_INTERNAL_IO_EXCEPTION -> DataFailCause.IWLAN_IKEV2_MSG_TIMEOUT;
+            case IwlanError.IKE_GENERIC_EXCEPTION -> DataFailCause.ERROR_UNSPECIFIED;
             case IwlanError.EPDG_SELECTOR_SERVER_SELECTION_FAILED ->
-                    ret = DataFailCause.IWLAN_DNS_RESOLUTION_NAME_FAILURE;
-            case IwlanError.TUNNEL_TRANSFORM_FAILED ->
-                    ret = DataFailCause.IWLAN_TUNNEL_TRANSFORM_FAILED;
-            case IwlanError.SIM_NOT_READY_EXCEPTION -> ret = DataFailCause.SIM_CARD_CHANGED;
+                    DataFailCause.IWLAN_DNS_RESOLUTION_NAME_FAILURE;
+            case IwlanError.TUNNEL_TRANSFORM_FAILED -> DataFailCause.IWLAN_TUNNEL_TRANSFORM_FAILED;
+            case IwlanError.SIM_NOT_READY_EXCEPTION -> DataFailCause.SIM_CARD_CHANGED;
             case IwlanError.IKE_SESSION_CLOSED_BEFORE_CHILD_SESSION_OPENED ->
-                    ret = DataFailCause.IWLAN_IKE_SESSION_CLOSED_BEFORE_CHILD_SESSION_OPENED;
+                    DataFailCause.IWLAN_IKE_SESSION_CLOSED_BEFORE_CHILD_SESSION_OPENED;
             case IwlanError.IKE_NETWORK_LOST_EXCEPTION ->
-                    ret = DataFailCause.IWLAN_IKE_NETWORK_LOST_EXCEPTION;
-            case IwlanError.TUNNEL_NOT_FOUND -> ret = DataFailCause.IWLAN_TUNNEL_NOT_FOUND;
-            case IwlanError.EPDG_ADDRESS_ONLY_IPV4_ALLOWED -> ret = DataFailCause.ONLY_IPV4_ALLOWED;
-            case IwlanError.EPDG_ADDRESS_ONLY_IPV6_ALLOWED -> ret = DataFailCause.ONLY_IPV6_ALLOWED;
-            case IwlanError.IKE_INIT_TIMEOUT -> ret = DataFailCause.IWLAN_IKE_INIT_TIMEOUT;
-            case IwlanError.IKE_MOBILITY_TIMEOUT -> ret = DataFailCause.IWLAN_IKE_MOBILITY_TIMEOUT;
-            case IwlanError.IKE_DPD_TIMEOUT -> ret = DataFailCause.IWLAN_IKE_DPD_TIMEOUT;
-            default -> ret = DataFailCause.ERROR_UNSPECIFIED;
-        }
-        return ret;
+                    DataFailCause.IWLAN_IKE_NETWORK_LOST_EXCEPTION;
+            case IwlanError.TUNNEL_NOT_FOUND -> DataFailCause.IWLAN_TUNNEL_NOT_FOUND;
+            case IwlanError.EPDG_ADDRESS_ONLY_IPV4_ALLOWED -> DataFailCause.ONLY_IPV4_ALLOWED;
+            case IwlanError.EPDG_ADDRESS_ONLY_IPV6_ALLOWED -> DataFailCause.ONLY_IPV6_ALLOWED;
+            case IwlanError.IKE_INIT_TIMEOUT -> DataFailCause.IWLAN_IKE_INIT_TIMEOUT;
+            case IwlanError.IKE_MOBILITY_TIMEOUT -> DataFailCause.IWLAN_IKE_MOBILITY_TIMEOUT;
+            case IwlanError.IKE_DPD_TIMEOUT -> DataFailCause.IWLAN_IKE_DPD_TIMEOUT;
+            default -> DataFailCause.ERROR_UNSPECIFIED;
+        };
     }
 
     // TODO: create DFC for all IkeProtocolExceptions and assign here.
@@ -319,48 +313,40 @@ public class ErrorPolicyManager {
         }
 
         int protocolErrorType = ikeProtocolException.getErrorType();
-        switch (protocolErrorType) {
-            case IkeProtocolException.ERROR_TYPE_AUTHENTICATION_FAILED:
-                return DataFailCause.IWLAN_IKEV2_AUTH_FAILURE;
-            case IkeProtocolException.ERROR_TYPE_INTERNAL_ADDRESS_FAILURE:
-                return DataFailCause.IWLAN_EPDG_INTERNAL_ADDRESS_FAILURE;
-            case IKE_PROTOCOL_ERROR_PDN_CONNECTION_REJECTION:
-                return DataFailCause.IWLAN_PDN_CONNECTION_REJECTION;
-            case IKE_PROTOCOL_ERROR_MAX_CONNECTION_REACHED:
-                return DataFailCause.IWLAN_MAX_CONNECTION_REACHED;
-            case IKE_PROTOCOL_ERROR_SEMANTIC_ERROR_IN_THE_TFT_OPERATION:
-                return DataFailCause.IWLAN_SEMANTIC_ERROR_IN_THE_TFT_OPERATION;
-            case IKE_PROTOCOL_ERROR_SYNTACTICAL_ERROR_IN_THE_TFT_OPERATION:
-                return DataFailCause.IWLAN_SYNTACTICAL_ERROR_IN_THE_TFT_OPERATION;
-            case IKE_PROTOCOL_ERROR_SEMANTIC_ERRORS_IN_PACKET_FILTERS:
-                return DataFailCause.IWLAN_SEMANTIC_ERRORS_IN_PACKET_FILTERS;
-            case IKE_PROTOCOL_ERROR_SYNTACTICAL_ERRORS_IN_PACKET_FILTERS:
-                return DataFailCause.IWLAN_SYNTACTICAL_ERRORS_IN_PACKET_FILTERS;
-            case IKE_PROTOCOL_ERROR_NON_3GPP_ACCESS_TO_EPC_NOT_ALLOWED:
-                return DataFailCause.IWLAN_NON_3GPP_ACCESS_TO_EPC_NOT_ALLOWED;
-            case IKE_PROTOCOL_ERROR_USER_UNKNOWN:
-                return DataFailCause.IWLAN_USER_UNKNOWN;
-            case IKE_PROTOCOL_ERROR_NO_APN_SUBSCRIPTION:
-                return DataFailCause.IWLAN_NO_APN_SUBSCRIPTION;
-            case IKE_PROTOCOL_ERROR_AUTHORIZATION_REJECTED:
-                return DataFailCause.IWLAN_AUTHORIZATION_REJECTED;
-            case IKE_PROTOCOL_ERROR_ILLEGAL_ME:
-                return DataFailCause.IWLAN_ILLEGAL_ME;
-            case IKE_PROTOCOL_ERROR_NETWORK_FAILURE:
-                return DataFailCause.IWLAN_NETWORK_FAILURE;
-            case IKE_PROTOCOL_ERROR_RAT_TYPE_NOT_ALLOWED:
-                return DataFailCause.IWLAN_RAT_TYPE_NOT_ALLOWED;
-            case IKE_PROTOCOL_ERROR_IMEI_NOT_ACCEPTED:
-                return DataFailCause.IWLAN_IMEI_NOT_ACCEPTED;
-            case IKE_PROTOCOL_ERROR_PLMN_NOT_ALLOWED:
-                return DataFailCause.IWLAN_PLMN_NOT_ALLOWED;
-            case IKE_PROTOCOL_ERROR_UNAUTHENTICATED_EMERGENCY_NOT_SUPPORTED:
-                return DataFailCause.IWLAN_UNAUTHENTICATED_EMERGENCY_NOT_SUPPORTED;
-            case IKE_PROTOCOL_ERROR_CONGESTION:
-                return DataFailCause.IWLAN_CONGESTION;
-            default:
-                return DataFailCause.IWLAN_IKE_PRIVATE_PROTOCOL_ERROR;
-        }
+        return switch (protocolErrorType) {
+            case IkeProtocolException.ERROR_TYPE_AUTHENTICATION_FAILED ->
+                    DataFailCause.IWLAN_IKEV2_AUTH_FAILURE;
+            case IkeProtocolException.ERROR_TYPE_INTERNAL_ADDRESS_FAILURE ->
+                    DataFailCause.IWLAN_EPDG_INTERNAL_ADDRESS_FAILURE;
+            case IKE_PROTOCOL_ERROR_PDN_CONNECTION_REJECTION ->
+                    DataFailCause.IWLAN_PDN_CONNECTION_REJECTION;
+            case IKE_PROTOCOL_ERROR_MAX_CONNECTION_REACHED ->
+                    DataFailCause.IWLAN_MAX_CONNECTION_REACHED;
+            case IKE_PROTOCOL_ERROR_SEMANTIC_ERROR_IN_THE_TFT_OPERATION ->
+                    DataFailCause.IWLAN_SEMANTIC_ERROR_IN_THE_TFT_OPERATION;
+            case IKE_PROTOCOL_ERROR_SYNTACTICAL_ERROR_IN_THE_TFT_OPERATION ->
+                    DataFailCause.IWLAN_SYNTACTICAL_ERROR_IN_THE_TFT_OPERATION;
+            case IKE_PROTOCOL_ERROR_SEMANTIC_ERRORS_IN_PACKET_FILTERS ->
+                    DataFailCause.IWLAN_SEMANTIC_ERRORS_IN_PACKET_FILTERS;
+            case IKE_PROTOCOL_ERROR_SYNTACTICAL_ERRORS_IN_PACKET_FILTERS ->
+                    DataFailCause.IWLAN_SYNTACTICAL_ERRORS_IN_PACKET_FILTERS;
+            case IKE_PROTOCOL_ERROR_NON_3GPP_ACCESS_TO_EPC_NOT_ALLOWED ->
+                    DataFailCause.IWLAN_NON_3GPP_ACCESS_TO_EPC_NOT_ALLOWED;
+            case IKE_PROTOCOL_ERROR_USER_UNKNOWN -> DataFailCause.IWLAN_USER_UNKNOWN;
+            case IKE_PROTOCOL_ERROR_NO_APN_SUBSCRIPTION -> DataFailCause.IWLAN_NO_APN_SUBSCRIPTION;
+            case IKE_PROTOCOL_ERROR_AUTHORIZATION_REJECTED ->
+                    DataFailCause.IWLAN_AUTHORIZATION_REJECTED;
+            case IKE_PROTOCOL_ERROR_ILLEGAL_ME -> DataFailCause.IWLAN_ILLEGAL_ME;
+            case IKE_PROTOCOL_ERROR_NETWORK_FAILURE -> DataFailCause.IWLAN_NETWORK_FAILURE;
+            case IKE_PROTOCOL_ERROR_RAT_TYPE_NOT_ALLOWED ->
+                    DataFailCause.IWLAN_RAT_TYPE_NOT_ALLOWED;
+            case IKE_PROTOCOL_ERROR_IMEI_NOT_ACCEPTED -> DataFailCause.IWLAN_IMEI_NOT_ACCEPTED;
+            case IKE_PROTOCOL_ERROR_PLMN_NOT_ALLOWED -> DataFailCause.IWLAN_PLMN_NOT_ALLOWED;
+            case IKE_PROTOCOL_ERROR_UNAUTHENTICATED_EMERGENCY_NOT_SUPPORTED ->
+                    DataFailCause.IWLAN_UNAUTHENTICATED_EMERGENCY_NOT_SUPPORTED;
+            case IKE_PROTOCOL_ERROR_CONGESTION -> DataFailCause.IWLAN_CONGESTION;
+            default -> DataFailCause.IWLAN_IKE_PRIVATE_PROTOCOL_ERROR;
+        };
     }
 
     public synchronized int getMostRecentDataFailCause() {
@@ -679,18 +665,15 @@ public class ErrorPolicyManager {
     private List<String> parseErrorDetails(int errorType, JSONArray errorDetailArray)
             throws JSONException, IllegalArgumentException {
         List<String> ret = new ArrayList<>();
-        boolean isValidErrorDetail = true;
 
         for (int i = 0; i < errorDetailArray.length(); i++) {
             String errorDetail = errorDetailArray.getString(i).trim();
-            switch (errorType) {
-                case IKE_PROTOCOL_ERROR_TYPE:
-                    isValidErrorDetail = verifyIkeProtocolErrorDetail(errorDetail);
-                    break;
-                case GENERIC_ERROR_TYPE:
-                    isValidErrorDetail = verifyGenericErrorDetail(errorDetail);
-                    break;
-            }
+            boolean isValidErrorDetail =
+                    switch (errorType) {
+                        case IKE_PROTOCOL_ERROR_TYPE -> verifyIkeProtocolErrorDetail(errorDetail);
+                        case GENERIC_ERROR_TYPE -> verifyGenericErrorDetail(errorDetail);
+                        default -> true;
+                    };
             if (!isValidErrorDetail) {
                 throw new IllegalArgumentException(
                         "Invalid ErrorDetail: " + errorDetail + " for ErrorType: " + errorType);
@@ -737,19 +720,12 @@ public class ErrorPolicyManager {
     }
 
     private @ErrorPolicyErrorType int getErrorPolicyErrorType(String errorType) {
-        int ret = UNKNOWN_ERROR_TYPE;
-        switch (errorType) {
-            case "IKE_PROTOCOL_ERROR_TYPE":
-                ret = IKE_PROTOCOL_ERROR_TYPE;
-                break;
-            case "GENERIC_ERROR_TYPE":
-                ret = GENERIC_ERROR_TYPE;
-                break;
-            case "*":
-                ret = FALLBACK_ERROR_TYPE;
-                break;
-        }
-        return ret;
+        return switch (errorType) {
+            case "IKE_PROTOCOL_ERROR_TYPE" -> IKE_PROTOCOL_ERROR_TYPE;
+            case "GENERIC_ERROR_TYPE" -> GENERIC_ERROR_TYPE;
+            case "*" -> FALLBACK_ERROR_TYPE;
+            default -> UNKNOWN_ERROR_TYPE;
+        };
     }
 
     private synchronized Set<Integer> getAllUnthrottlingEvents() {
@@ -991,38 +967,20 @@ public class ErrorPolicyManager {
         }
 
         String getGenericErrorDetailString(IwlanError iwlanError) {
-            String ret = "UNKNOWN";
-            switch (iwlanError.getErrorType()) {
-                case IwlanError.IKE_INTERNAL_IO_EXCEPTION:
-                    ret = "IO_EXCEPTION";
-                    break;
-                case IwlanError.EPDG_SELECTOR_SERVER_SELECTION_FAILED:
-                    ret = "SERVER_SELECTION_FAILED";
-                    break;
-                case IwlanError.TUNNEL_TRANSFORM_FAILED:
-                    ret = "TUNNEL_TRANSFORM_FAILED";
-                    break;
-                case IwlanError.IKE_NETWORK_LOST_EXCEPTION:
-                    ret = "IKE_NETWORK_LOST_EXCEPTION";
-                    break;
-                case IwlanError.EPDG_ADDRESS_ONLY_IPV4_ALLOWED:
-                    ret = "EPDG_ADDRESS_ONLY_IPV4_ALLOWED";
-                    break;
-                case IwlanError.EPDG_ADDRESS_ONLY_IPV6_ALLOWED:
-                    ret = "EPDG_ADDRESS_ONLY_IPV6_ALLOWED";
-                    break;
-                    // TODO: Add TIMEOUT_EXCEPTION processing
-                case IwlanError.IKE_INIT_TIMEOUT:
-                    ret = "IKE_INIT_TIMEOUT";
-                    break;
-                case IwlanError.IKE_MOBILITY_TIMEOUT:
-                    ret = "IKE_MOBILITY_TIMEOUT";
-                    break;
-                case IwlanError.IKE_DPD_TIMEOUT:
-                    ret = "IKE_DPD_TIMEOUT";
-                    break;
-            }
-            return ret;
+            return switch (iwlanError.getErrorType()) {
+                case IwlanError.IKE_INTERNAL_IO_EXCEPTION -> "IO_EXCEPTION";
+                case IwlanError.EPDG_SELECTOR_SERVER_SELECTION_FAILED -> "SERVER_SELECTION_FAILED";
+                case IwlanError.TUNNEL_TRANSFORM_FAILED -> "TUNNEL_TRANSFORM_FAILED";
+                case IwlanError.IKE_NETWORK_LOST_EXCEPTION -> "IKE_NETWORK_LOST_EXCEPTION";
+                case IwlanError.EPDG_ADDRESS_ONLY_IPV4_ALLOWED -> "EPDG_ADDRESS_ONLY_IPV4_ALLOWED";
+                case IwlanError.EPDG_ADDRESS_ONLY_IPV6_ALLOWED -> "EPDG_ADDRESS_ONLY_IPV6_ALLOWED";
+                // TODO: Add TIMEOUT_EXCEPTION processing
+                // TODO: Add all the missing error detail string
+                case IwlanError.IKE_INIT_TIMEOUT -> "IKE_INIT_TIMEOUT";
+                case IwlanError.IKE_MOBILITY_TIMEOUT -> "IKE_MOBILITY_TIMEOUT";
+                case IwlanError.IKE_DPD_TIMEOUT -> "IKE_DPD_TIMEOUT";
+                default -> "UNKNOWN";
+            };
         }
     }
 
@@ -1049,10 +1007,13 @@ public class ErrorPolicyManager {
     }
 
     /** RetryAction with retry time defined by retry index and error policy */
-    @AutoValue
-    abstract static class PolicyDerivedRetryAction implements RetryAction {
-        abstract int currentRetryIndex();
-
+    record PolicyDerivedRetryAction(
+            @Override IwlanError error,
+            @Override ErrorPolicy errorPolicy,
+            @Override long lastErrorTime,
+            @Override int errorCountOfSameCause,
+            int currentRetryIndex)
+            implements RetryAction {
         @Override
         public long totalRetryTimeMs() {
             return TimeUnit.SECONDS.toMillis(errorPolicy().getRetryTime(currentRetryIndex()));
@@ -1074,27 +1035,16 @@ public class ErrorPolicyManager {
             return errorPolicy.getErrorType() == IKE_PROTOCOL_ERROR_TYPE
                     && currentRetryIndex() + 1 >= errorPolicy.getHandoverAttemptCount();
         }
-
-        /** Create a new PolicyDerivedRetryAction */
-        static PolicyDerivedRetryAction create(
-                IwlanError error,
-                ErrorPolicy errorPolicy,
-                int errorCountOfSameCause,
-                int currentRetryIndex) {
-            return new AutoValue_ErrorPolicyManager_PolicyDerivedRetryAction(
-                    error,
-                    errorPolicy,
-                    IwlanHelper.elapsedRealtime(),
-                    errorCountOfSameCause,
-                    currentRetryIndex);
-        }
     }
 
     /** RetryAction with retry time defined by backoff time in tunnel config */
-    @AutoValue
-    abstract static class IkeBackoffNotifyRetryAction implements RetryAction {
-        abstract long backoffTime();
-
+    record IkeBackoffNotifyRetryAction(
+            @Override IwlanError error,
+            @Override ErrorPolicy errorPolicy,
+            @Override long lastErrorTime,
+            @Override int errorCountOfSameCause,
+            long backoffTime)
+            implements RetryAction {
         @Override
         public long totalRetryTimeMs() {
             return TimeUnit.SECONDS.toMillis(backoffTime());
@@ -1113,19 +1063,6 @@ public class ErrorPolicyManager {
             return errorPolicy.getErrorType() == IKE_PROTOCOL_ERROR_TYPE
                     && errorPolicy.getHandoverAttemptCount() == 0;
         }
-
-        static IkeBackoffNotifyRetryAction create(
-                IwlanError error,
-                ErrorPolicy errorPolicy,
-                int errorCountOfSameCause,
-                long backoffTime) {
-            return new AutoValue_ErrorPolicyManager_IkeBackoffNotifyRetryAction(
-                    error,
-                    errorPolicy,
-                    IwlanHelper.elapsedRealtime(),
-                    errorCountOfSameCause,
-                    backoffTime);
-        }
     }
 
     interface ErrorCause {
@@ -1224,8 +1161,12 @@ public class ErrorPolicyManager {
 
             ErrorPolicy policy = findErrorPolicy(mApn, iwlanError);
             PolicyDerivedRetryAction newRetryAction =
-                    PolicyDerivedRetryAction.create(
-                            iwlanError, policy, newErrorCount, newRetryIndex);
+                    new PolicyDerivedRetryAction(
+                            iwlanError,
+                            policy,
+                            IwlanHelper.elapsedRealtime(),
+                            newErrorCount,
+                            newRetryIndex);
             mLastRetryActionByCause.put(errorCause, newRetryAction);
             mLastRetryAction = newRetryAction;
 
@@ -1242,8 +1183,12 @@ public class ErrorPolicyManager {
             // For configured back off time case, simply create new RetryAction, nothing need to
             // keep
             IkeBackoffNotifyRetryAction newRetryAction =
-                    IkeBackoffNotifyRetryAction.create(
-                            iwlanError, policy, newErrorCount, backoffTime);
+                    new IkeBackoffNotifyRetryAction(
+                            iwlanError,
+                            policy,
+                            IwlanHelper.elapsedRealtime(),
+                            newErrorCount,
+                            backoffTime);
             mLastRetryActionByCause.put(errorCause, newRetryAction);
             mLastRetryAction = newRetryAction;
 
diff --git a/src/com/google/android/iwlan/IwlanBroadcastReceiver.java b/src/com/google/android/iwlan/IwlanBroadcastReceiver.java
index ddc9e7a..025f455 100644
--- a/src/com/google/android/iwlan/IwlanBroadcastReceiver.java
+++ b/src/com/google/android/iwlan/IwlanBroadcastReceiver.java
@@ -21,16 +21,8 @@ import android.content.Context;
 import android.content.Intent;
 import android.content.IntentFilter;
 import android.net.wifi.WifiManager;
-import android.telephony.CarrierConfigManager;
-import android.telephony.SubscriptionManager;
-import android.telephony.TelephonyManager;
-import android.telephony.data.ApnSetting;
 import android.util.Log;
 
-import com.google.android.iwlan.epdg.EpdgSelector;
-
-import java.util.Arrays;
-
 public class IwlanBroadcastReceiver extends BroadcastReceiver {
     private static final String TAG = "IwlanBroadcastReceiver";
 
@@ -45,6 +37,7 @@ public class IwlanBroadcastReceiver extends BroadcastReceiver {
         IntentFilter intentFilter = new IntentFilter();
         intentFilter.addAction(WifiManager.WIFI_STATE_CHANGED_ACTION);
         intentFilter.addAction(Intent.ACTION_AIRPLANE_MODE_CHANGED);
+        intentFilter.addAction(Intent.ACTION_SCREEN_ON);
         context.registerReceiver(getInstance(), intentFilter);
         mIsReceiverRegistered = true;
     }
@@ -72,81 +65,9 @@ public class IwlanBroadcastReceiver extends BroadcastReceiver {
         switch (action) {
             case Intent.ACTION_AIRPLANE_MODE_CHANGED:
             case WifiManager.WIFI_STATE_CHANGED_ACTION:
+            case Intent.ACTION_SCREEN_ON:
                 IwlanEventListener.onBroadcastReceived(intent);
                 break;
-            case TelephonyManager.ACTION_CARRIER_SIGNAL_PCO_VALUE:
-                processCarrierSignalPcoValue(intent);
-                break;
-        }
-    }
-
-    private void processCarrierSignalPcoValue(Intent intent) {
-        Log.d(TAG, "on CARRIER_SIGNAL_PCO_VALUE intent");
-        int intentSubId =
-                intent.getIntExtra(
-                        SubscriptionManager.EXTRA_SUBSCRIPTION_INDEX,
-                        SubscriptionManager.INVALID_SUBSCRIPTION_ID);
-        int intentSlotIndex = SubscriptionManager.getSlotIndex(intentSubId);
-        Log.d(TAG, "intentSubId:" + intentSubId + " intentSlotIndex:" + intentSlotIndex);
-
-        if (intentSlotIndex != SubscriptionManager.INVALID_SIM_SLOT_INDEX) {
-
-            int apnBitMask = intent.getIntExtra(TelephonyManager.EXTRA_APN_TYPE, 0);
-
-            if ((apnBitMask & ApnSetting.TYPE_IMS) != 0) {
-                int pcoId = intent.getIntExtra(TelephonyManager.EXTRA_PCO_ID, 0);
-                byte[] pcoData = intent.getByteArrayExtra(TelephonyManager.EXTRA_PCO_VALUE);
-
-                if (pcoData == null) {
-                    Log.e(TAG, "Pco data unavailable");
-                    return;
-                }
-
-                Log.d(
-                        TAG,
-                        "PcoID:"
-                                + String.format("0x%04x", pcoId)
-                                + " PcoData:"
-                                + Arrays.toString(pcoData));
-
-                Context mContext = IwlanDataService.getContext();
-
-                if (mContext != null) {
-                    int PCO_ID_IPv6 =
-                            IwlanCarrierConfig.getConfigInt(
-                                    mContext,
-                                    intentSlotIndex,
-                                    CarrierConfigManager.Iwlan.KEY_EPDG_PCO_ID_IPV6_INT);
-
-                    int PCO_ID_IPv4 =
-                            IwlanCarrierConfig.getConfigInt(
-                                    mContext,
-                                    intentSlotIndex,
-                                    CarrierConfigManager.Iwlan.KEY_EPDG_PCO_ID_IPV4_INT);
-
-                    Log.d(
-                            TAG,
-                            "PCO_ID_IPv6:"
-                                    + String.format("0x%04x", PCO_ID_IPv6)
-                                    + " PCO_ID_IPv4:"
-                                    + String.format("0x%04x", PCO_ID_IPv4));
-
-                    if (pcoId == PCO_ID_IPv6 || pcoId == PCO_ID_IPv4) {
-                        Log.d(TAG, "SetPcoData to EpdgSelector");
-                        EpdgSelector selector =
-                                EpdgSelector.getSelectorInstance(mContext, intentSlotIndex);
-                        boolean ret = selector.setPcoData(pcoId, pcoData);
-                    } else {
-                        Log.d(TAG, "Unwanted PcoID " + pcoId);
-                    }
-                } else {
-                    Log.e(TAG, "Null context");
-                }
-            } else {
-                Log.d(TAG, "Unwanted Apntype " + apnBitMask);
-            }
-        } else {
-            Log.e(TAG, "Invalid slot index");
         }
     }
 }
diff --git a/src/com/google/android/iwlan/IwlanCarrierConfig.java b/src/com/google/android/iwlan/IwlanCarrierConfig.java
index e16ff8f..822ff3f 100644
--- a/src/com/google/android/iwlan/IwlanCarrierConfig.java
+++ b/src/com/google/android/iwlan/IwlanCarrierConfig.java
@@ -18,6 +18,7 @@ package com.google.android.iwlan;
 
 import android.content.Context;
 import android.os.PersistableBundle;
+import android.support.annotation.IntDef;
 import android.support.annotation.NonNull;
 import android.telephony.CarrierConfigManager;
 
@@ -65,12 +66,41 @@ public class IwlanCarrierConfig {
             PREFIX + "ike_device_identity_supported_bool";
 
     /**
-     * Boolean indicating if reordering ike SA transforms enabled. Refer to
-     * {@link #DEFAULT_IKE_SA_TRANSFORMS_REORDER_BOOL} for the default value.
+     * Boolean indicating if reordering ike SA transforms enabled. Refer to {@link
+     * #DEFAULT_IKE_SA_TRANSFORMS_REORDER_BOOL} for the default value.
      */
     public static final String KEY_IKE_SA_TRANSFORMS_REORDER_BOOL =
             PREFIX + "ike_sa_transforms_reorder_bool";
 
+    /** Trigger network validation when making a call */
+    public static final int NETWORK_VALIDATION_EVENT_MAKING_CALL = 0;
+
+    /** Trigger network validation when screen on */
+    public static final int NETWORK_VALIDATION_EVENT_SCREEN_ON = 1;
+
+    /** Trigger network validation when no response on network */
+    public static final int NETWORK_VALIDATION_EVENT_NO_RESPONSE = 2;
+
+    @IntDef({
+        NETWORK_VALIDATION_EVENT_MAKING_CALL,
+        NETWORK_VALIDATION_EVENT_SCREEN_ON,
+        NETWORK_VALIDATION_EVENT_NO_RESPONSE
+    })
+    public @interface NetworkValidationEvent {}
+
+    /**
+     * Key to control which events should trigger IWLAN underlying network validation when specific
+     * event received, possible values in the int array:
+     *
+     * <ul>
+     *   <li>0: NETWORK_VALIDATION_EVENT_MAKING_CALL
+     *   <li>1: NETWORK_VALIDATION_EVENT_SCREEN_ON
+     *   <li>2: NETWORK_VALIDATION_EVENT_NO_RESPONSE
+     * </ul>
+     */
+    public static final String KEY_UNDERLYING_NETWORK_VALIDATION_EVENTS_INT_ARRAY =
+            PREFIX + "underlying_network_validation_events_int_array";
+
     /**
      * IWLAN error policy configs that determine the behavior when error happens during ePDG tunnel
      * setup. Refer to {@link #DEFAULT_ERROR_POLICY_CONFIG_STRING} for the default value.
@@ -170,6 +200,7 @@ public class IwlanCarrierConfig {
 
     /** This is the default value for {@link #KEY_DISTINCT_EPDG_FOR_EMERGENCY_ALLOWED_BOOL}. */
     public static final boolean DEFAULT_DISTINCT_EPDG_FOR_EMERGENCY_ALLOWED_BOOL = false;
+
     /**
      * Default value indicating whether the UE includes the IKE DEVICE_IDENTITY Notify payload upon
      * receiving a request. This is the default setting for {@link
@@ -180,6 +211,12 @@ public class IwlanCarrierConfig {
     /** This is the default value for {@link #KEY_IKE_SA_TRANSFORMS_REORDER_BOOL}. */
     public static final boolean DEFAULT_IKE_SA_TRANSFORMS_REORDER_BOOL = false;
 
+    /**
+     * The default value of which events should trigger IWLAN underlying network validation. This is
+     * the default value for {@link #KEY_UNDERLYING_NETWORK_VALIDATION_EVENTS_INT_ARRAY}
+     */
+    public static final int[] DEFAULT_UNDERLYING_NETWORK_VALIDATION_EVENTS_INT_ARRAY = {};
+
     /**
      * The default value for determining IWLAN's behavior when error happens during ePDG tunnel
      * setup. This is the default value for {@link #KEY_ERROR_POLICY_CONFIG_STRING}.
@@ -246,6 +283,9 @@ public class IwlanCarrierConfig {
                 KEY_IKE_DEVICE_IDENTITY_SUPPORTED_BOOL, DEFAULT_IKE_DEVICE_IDENTITY_SUPPORTED_BOOL);
         bundle.putBoolean(
                 KEY_IKE_SA_TRANSFORMS_REORDER_BOOL, DEFAULT_IKE_SA_TRANSFORMS_REORDER_BOOL);
+        bundle.putIntArray(
+                KEY_UNDERLYING_NETWORK_VALIDATION_EVENTS_INT_ARRAY,
+                DEFAULT_UNDERLYING_NETWORK_VALIDATION_EVENTS_INT_ARRAY);
         bundle.putString(KEY_ERROR_POLICY_CONFIG_STRING, DEFAULT_ERROR_POLICY_CONFIG_STRING);
         return bundle;
     }
@@ -568,4 +608,14 @@ public class IwlanCarrierConfig {
     public static void resetTestConfig() {
         sTestBundle.clear();
     }
+
+    public static String getUnderlyingNetworkValidationEventString(
+            @IwlanCarrierConfig.NetworkValidationEvent int event) {
+        return switch (event) {
+            case IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_MAKING_CALL -> "MAKING_CALL";
+            case IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_SCREEN_ON -> "SCREEN_ON";
+            case IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_NO_RESPONSE -> "NO_RESPONSE";
+            default -> "UNKNOWN";
+        };
+    }
 }
diff --git a/src/com/google/android/iwlan/IwlanDataService.java b/src/com/google/android/iwlan/IwlanDataService.java
index 9ffe86f..80029fa 100644
--- a/src/com/google/android/iwlan/IwlanDataService.java
+++ b/src/com/google/android/iwlan/IwlanDataService.java
@@ -70,12 +70,9 @@ import com.android.internal.annotations.VisibleForTesting;
 
 import com.google.android.iwlan.TunnelMetricsInterface.OnClosedMetrics;
 import com.google.android.iwlan.TunnelMetricsInterface.OnOpenedMetrics;
-import com.google.android.iwlan.epdg.EpdgSelector;
 import com.google.android.iwlan.epdg.EpdgTunnelManager;
 import com.google.android.iwlan.epdg.TunnelLinkProperties;
 import com.google.android.iwlan.epdg.TunnelSetupRequest;
-import com.google.android.iwlan.flags.FeatureFlags;
-import com.google.android.iwlan.flags.FeatureFlagsImpl;
 import com.google.android.iwlan.proto.MetricsAtom;
 
 import java.io.FileDescriptor;
@@ -99,7 +96,6 @@ import java.util.function.Consumer;
 
 public class IwlanDataService extends DataService {
 
-    private final FeatureFlags mFeatureFlags;
     private static final String TAG = IwlanDataService.class.getSimpleName();
 
     private static final String CONTEXT_ATTRIBUTION_TAG = "IWLAN";
@@ -109,8 +105,8 @@ public class IwlanDataService extends DataService {
     private static Network sNetwork = null;
     private static LinkProperties sLinkProperties = null;
     private static NetworkCapabilities sNetworkCapabilities;
-    @VisibleForTesting Handler mIwlanDataServiceHandler;
-    private HandlerThread mIwlanDataServiceHandlerThread;
+    @VisibleForTesting Handler mHandler;
+    private HandlerThread mHandlerThread;
     private static final Map<Integer, IwlanDataServiceProvider> sIwlanDataServiceProviders =
             new ConcurrentHashMap<>();
     private static final int INVALID_SUB_ID = -1;
@@ -120,16 +116,11 @@ public class IwlanDataService extends DataService {
     private static int mConnectedDataSub = INVALID_SUB_ID;
 
     private static final int EVENT_BASE = IwlanEventListener.DATA_SERVICE_INTERNAL_EVENT_BASE;
-    private static final int EVENT_TUNNEL_OPENED = EVENT_BASE;
-    private static final int EVENT_TUNNEL_CLOSED = EVENT_BASE + 1;
-    private static final int EVENT_SETUP_DATA_CALL = EVENT_BASE + 2;
     private static final int EVENT_DEACTIVATE_DATA_CALL = EVENT_BASE + 3;
     private static final int EVENT_DATA_CALL_LIST_REQUEST = EVENT_BASE + 4;
     private static final int EVENT_FORCE_CLOSE_TUNNEL = EVENT_BASE + 5;
     private static final int EVENT_ADD_DATA_SERVICE_PROVIDER = EVENT_BASE + 6;
     private static final int EVENT_REMOVE_DATA_SERVICE_PROVIDER = EVENT_BASE + 7;
-    private static final int EVENT_TUNNEL_OPENED_METRICS = EVENT_BASE + 8;
-    private static final int EVENT_TUNNEL_CLOSED_METRICS = EVENT_BASE + 9;
     private static final int EVENT_DEACTIVATE_DATA_CALL_WITH_DELAY = EVENT_BASE + 10;
     private static final int EVENT_ON_LIVENESS_STATUS_CHANGED = EVENT_BASE + 11;
     private static final int EVENT_REQUEST_NETWORK_VALIDATION = EVENT_BASE + 12;
@@ -145,14 +136,7 @@ public class IwlanDataService extends DataService {
 
     private boolean mIs5GEnabledOnUi;
 
-    public IwlanDataService() {
-        mFeatureFlags = new FeatureFlagsImpl();
-    }
-
-    @VisibleForTesting
-    IwlanDataService(FeatureFlags featureFlags) {
-        mFeatureFlags = featureFlags;
-    }
+    public IwlanDataService() {}
 
     // TODO: see if network monitor callback impl can be shared between dataservice and
     // networkservice
@@ -249,11 +233,11 @@ public class IwlanDataService extends DataService {
 
         private final String SUB_TAG;
         private final IwlanDataService mIwlanDataService;
+        // TODO(b/358152549): Remove metrics handling inside IwlanTunnelCallback
         private final IwlanTunnelCallback mIwlanTunnelCallback;
-        private final IwlanTunnelMetricsImpl mIwlanTunnelMetrics;
+        private final EpdgTunnelManager mEpdgTunnelManager;
         private boolean mWfcEnabled = false;
         private boolean mCarrierConfigReady = false;
-        private final EpdgSelector mEpdgSelector;
         private final IwlanDataTunnelStats mTunnelStats;
         private CellInfo mCellInfo = null;
         private int mCallState = TelephonyManager.CALL_STATE_IDLE;
@@ -425,24 +409,16 @@ public class IwlanDataService extends DataService {
             @Override
             public String toString() {
                 StringBuilder sb = new StringBuilder();
-                String tunnelState = "UNKNOWN";
-                switch (mState) {
-                    case TUNNEL_DOWN:
-                        tunnelState = "DOWN";
-                        break;
-                    case TUNNEL_IN_BRINGUP:
-                        tunnelState = "IN BRINGUP";
-                        break;
-                    case TUNNEL_UP:
-                        tunnelState = "UP";
-                        break;
-                    case TUNNEL_IN_BRINGDOWN:
-                        tunnelState = "IN BRINGDOWN";
-                        break;
-                    case TUNNEL_IN_FORCE_CLEAN_WAS_IN_BRINGUP:
-                        tunnelState = "IN FORCE CLEAN WAS IN BRINGUP";
-                        break;
-                }
+                String tunnelState =
+                        switch (mState) {
+                            case TUNNEL_DOWN -> "DOWN";
+                            case TUNNEL_IN_BRINGUP -> "IN BRINGUP";
+                            case TUNNEL_UP -> "UP";
+                            case TUNNEL_IN_BRINGDOWN -> "IN BRINGDOWN";
+                            case TUNNEL_IN_FORCE_CLEAN_WAS_IN_BRINGUP ->
+                                    "IN FORCE CLEAN WAS IN BRINGUP";
+                            default -> "UNKNOWN";
+                        };
                 sb.append("\tCurrent State of this tunnel: ")
                         .append(mState)
                         .append(" ")
@@ -478,34 +454,31 @@ public class IwlanDataService extends DataService {
 
             // TODO: full implementation
 
-            public void onOpened(String apnName, TunnelLinkProperties linkProperties) {
-                Log.d(
-                        SUB_TAG,
-                        "Tunnel opened! APN: " + apnName + ", linkProperties: " + linkProperties);
-                getIwlanDataServiceHandler()
-                        .sendMessage(
-                                getIwlanDataServiceHandler()
-                                        .obtainMessage(
-                                                EVENT_TUNNEL_OPENED,
-                                                new TunnelOpenedData(
-                                                        apnName,
-                                                        linkProperties,
-                                                        mIwlanDataServiceProvider)));
-            }
-
-            public void onClosed(String apnName, IwlanError error) {
+            public void onOpened(
+                    String apnName,
+                    TunnelLinkProperties linkProperties,
+                    OnOpenedMetrics onOpenedMetrics) {
+                postToHandler(
+                        () ->
+                                handleTunnelOpened(
+                                        apnName,
+                                        linkProperties,
+                                        mIwlanDataServiceProvider,
+                                        onOpenedMetrics));
+            }
+
+            public void onClosed(
+                    String apnName, IwlanError error, OnClosedMetrics onClosedMetrics) {
                 Log.d(SUB_TAG, "Tunnel closed! APN: " + apnName + ", Error: " + error);
                 // this is called, when a tunnel that is up, is closed.
                 // the expectation is error==NO_ERROR for user initiated/normal close.
-                getIwlanDataServiceHandler()
-                        .sendMessage(
-                                getIwlanDataServiceHandler()
-                                        .obtainMessage(
-                                                EVENT_TUNNEL_CLOSED,
-                                                new TunnelClosedData(
-                                                        apnName,
-                                                        error,
-                                                        mIwlanDataServiceProvider)));
+                postToHandler(
+                        () ->
+                                handleTunnelClosed(
+                                        apnName,
+                                        error,
+                                        mIwlanDataServiceProvider,
+                                        onClosedMetrics));
             }
 
             public void onNetworkValidationStatusChanged(
@@ -517,7 +490,7 @@ public class IwlanDataService extends DataService {
                                 + ", status: "
                                 + PreciseDataConnectionState.networkValidationStatusToString(
                                         status));
-                getIwlanDataServiceHandler()
+                getHandler()
                         .obtainMessage(
                                 EVENT_ON_LIVENESS_STATUS_CHANGED,
                                 new TunnelValidationStatusData(
@@ -679,8 +652,7 @@ public class IwlanDataService extends DataService {
             // get reference to resolver
             mIwlanDataService = iwlanDataService;
             mIwlanTunnelCallback = new IwlanTunnelCallback(this);
-            mIwlanTunnelMetrics = new IwlanTunnelMetricsImpl(this, getIwlanDataServiceHandler());
-            mEpdgSelector = EpdgSelector.getSelectorInstance(mContext, slotIndex);
+            mEpdgTunnelManager = EpdgTunnelManager.getInstance(mContext, slotIndex);
             mCalendar = Calendar.getInstance();
             mTunnelStats = new IwlanDataTunnelStats();
 
@@ -694,12 +666,9 @@ public class IwlanDataService extends DataService {
             events.add(IwlanEventListener.CELLINFO_CHANGED_EVENT);
             events.add(IwlanEventListener.CALL_STATE_CHANGED_EVENT);
             events.add(IwlanEventListener.PREFERRED_NETWORK_TYPE_CHANGED_EVENT);
+            events.add(IwlanEventListener.SCREEN_ON_EVENT);
             IwlanEventListener.getInstance(mContext, slotIndex)
-                    .addEventListener(events, getIwlanDataServiceHandler());
-        }
-
-        private EpdgTunnelManager getTunnelManager() {
-            return EpdgTunnelManager.getInstance(mContext, getSlotIndex());
+                    .addEventListener(events, getHandler());
         }
 
         // creates a DataCallResponse for an apn irrespective of state
@@ -869,21 +838,6 @@ public class IwlanDataService extends DataService {
                             + ", linkProperties: "
                             + linkProperties);
 
-            SetupDataCallData setupDataCallData =
-                    new SetupDataCallData(
-                            accessNetworkType,
-                            dataProfile,
-                            isRoaming,
-                            allowRoaming,
-                            reason,
-                            linkProperties,
-                            pduSessionId,
-                            sliceInfo,
-                            trafficDescriptor,
-                            matchAllRuleAllowed,
-                            callback,
-                            this);
-
             int networkTransport = -1;
             if (sDefaultDataTransport == Transport.MOBILE) {
                 networkTransport = TRANSPORT_CELLULAR;
@@ -909,11 +863,17 @@ public class IwlanDataService extends DataService {
                         // Transport Type
                         networkTransport);
             }
-
-            getIwlanDataServiceHandler()
-                    .sendMessage(
-                            getIwlanDataServiceHandler()
-                                    .obtainMessage(EVENT_SETUP_DATA_CALL, setupDataCallData));
+            postToHandler(
+                    () ->
+                            handleSetupDataCall(
+                                    accessNetworkType,
+                                    dataProfile,
+                                    isRoaming,
+                                    reason,
+                                    linkProperties,
+                                    pduSessionId,
+                                    callback,
+                                    this));
         }
 
         /**
@@ -964,9 +924,7 @@ public class IwlanDataService extends DataService {
             DeactivateDataCallData deactivateDataCallData =
                     new DeactivateDataCallData(cid, reason, callback, this, delayTimeSeconds);
 
-            getIwlanDataServiceHandler()
-                    .obtainMessage(event, deactivateDataCallData)
-                    .sendToTarget();
+            getHandler().obtainMessage(event, deactivateDataCallData).sendToTarget();
         }
 
         /**
@@ -1001,7 +959,7 @@ public class IwlanDataService extends DataService {
             Objects.requireNonNull(resultCodeCallback, "resultCodeCallback cannot be null");
             Log.d(TAG, "request Network Validation: " + cid);
 
-            getIwlanDataServiceHandler()
+            getHandler()
                     .obtainMessage(
                             EVENT_REQUEST_NETWORK_VALIDATION,
                             new NetworkValidationInfo(cid, executor, resultCodeCallback, this))
@@ -1012,13 +970,11 @@ public class IwlanDataService extends DataService {
             for (Map.Entry<String, TunnelState> entry : mTunnelStateForApn.entrySet()) {
                 TunnelState tunnelState = entry.getValue();
                 if (tunnelState.getState() == TunnelState.TUNNEL_IN_BRINGDOWN) {
-                    getTunnelManager()
-                            .closeTunnel(
-                                    entry.getKey(),
-                                    true /* forceClose */,
-                                    getIwlanTunnelCallback(),
-                                    getIwlanTunnelMetrics(),
-                                    BRINGDOWN_REASON_IN_DEACTIVATING_STATE);
+                    mEpdgTunnelManager.closeTunnel(
+                            entry.getKey(),
+                            true /* forceClose */,
+                            getIwlanTunnelCallback(),
+                            BRINGDOWN_REASON_IN_DEACTIVATING_STATE);
                 }
             }
         }
@@ -1031,13 +987,8 @@ public class IwlanDataService extends DataService {
          */
         void forceCloseTunnels(@EpdgTunnelManager.TunnelBringDownReason int reason) {
             for (Map.Entry<String, TunnelState> entry : mTunnelStateForApn.entrySet()) {
-                getTunnelManager()
-                        .closeTunnel(
-                                entry.getKey(),
-                                true /* forceClose */,
-                                getIwlanTunnelCallback(),
-                                getIwlanTunnelMetrics(),
-                                reason);
+                mEpdgTunnelManager.closeTunnel(
+                        entry.getKey(), true /* forceClose */, getIwlanTunnelCallback(), reason);
             }
         }
 
@@ -1048,13 +999,11 @@ public class IwlanDataService extends DataService {
          */
         @Override
         public void requestDataCallList(DataServiceCallback callback) {
-            getIwlanDataServiceHandler()
-                    .sendMessage(
-                            getIwlanDataServiceHandler()
-                                    .obtainMessage(
-                                            EVENT_DATA_CALL_LIST_REQUEST,
-                                            new DataCallRequestData(
-                                                    callback, IwlanDataServiceProvider.this)));
+            getHandler()
+                    .obtainMessage(
+                            EVENT_DATA_CALL_LIST_REQUEST,
+                            new DataCallRequestData(callback, IwlanDataServiceProvider.this))
+                    .sendToTarget();
         }
 
         @VisibleForTesting
@@ -1109,11 +1058,6 @@ public class IwlanDataService extends DataService {
             return mIwlanTunnelCallback;
         }
 
-        @VisibleForTesting
-        public IwlanTunnelMetricsImpl getIwlanTunnelMetrics() {
-            return mIwlanTunnelMetrics;
-        }
-
         @VisibleForTesting
         IwlanDataTunnelStats getTunnelStats() {
             return mTunnelStats;
@@ -1124,7 +1068,7 @@ public class IwlanDataService extends DataService {
             if (isNetworkConnected(
                     isActiveDataOnOtherSub(getSlotIndex()),
                     IwlanHelper.isCrossSimCallingEnabled(mContext, getSlotIndex()))) {
-                getTunnelManager().updateNetwork(network, linkProperties);
+                mEpdgTunnelManager.updateNetwork(network, linkProperties);
             }
 
             if (Objects.equals(network, sNetwork)) {
@@ -1138,13 +1082,11 @@ public class IwlanDataService extends DataService {
                     // This may not result in actual closing of Ike Session since
                     // epdg selection may not be complete yet.
                     tunnelState.setState(TunnelState.TUNNEL_IN_FORCE_CLEAN_WAS_IN_BRINGUP);
-                    getTunnelManager()
-                            .closeTunnel(
-                                    entry.getKey(),
-                                    true /* forceClose */,
-                                    getIwlanTunnelCallback(),
-                                    getIwlanTunnelMetrics(),
-                                    BRINGDOWN_REASON_NETWORK_UPDATE_WHEN_TUNNEL_IN_BRINGUP);
+                    mEpdgTunnelManager.closeTunnel(
+                            entry.getKey(),
+                            true /* forceClose */,
+                            getIwlanTunnelCallback(),
+                            BRINGDOWN_REASON_NETWORK_UPDATE_WHEN_TUNNEL_IN_BRINGUP);
                 }
             }
         }
@@ -1155,7 +1097,7 @@ public class IwlanDataService extends DataService {
                     continue;
                 }
 
-                if (mCellInfo == null || mCellInfo != cellInfo) {
+                if (mCellInfo == null || !mCellInfo.equals(cellInfo)) {
                     mCellInfo = cellInfo;
                     Log.d(TAG, " Update cached cellinfo");
                     return true;
@@ -1169,7 +1111,7 @@ public class IwlanDataService extends DataService {
                     isNetworkConnected(
                             isActiveDataOnOtherSub(getSlotIndex()),
                             IwlanHelper.isCrossSimCallingEnabled(mContext, getSlotIndex()));
-            /* Check if we need to do prefecting */
+            /* Check if we need to do prefetching */
             if (networkConnected
                     && mCarrierConfigReady
                     && mWfcEnabled
@@ -1183,30 +1125,10 @@ public class IwlanDataService extends DataService {
                                 IwlanHelper.getSubId(mContext, getSlotIndex()));
                 boolean isRoaming = telephonyManager.isNetworkRoaming();
                 Log.d(TAG, "Trigger EPDG prefetch. Roaming=" + isRoaming);
-
-                prefetchEpdgServerList(sNetwork, isRoaming);
+                mEpdgTunnelManager.prefetchEpdgServerList(sNetwork, isRoaming);
             }
         }
 
-        private void prefetchEpdgServerList(Network network, boolean isRoaming) {
-            mEpdgSelector.getValidatedServerList(
-                    0,
-                    EpdgSelector.PROTO_FILTER_IPV4V6,
-                    EpdgSelector.SYSTEM_PREFERRED,
-                    isRoaming,
-                    false,
-                    network,
-                    null);
-            mEpdgSelector.getValidatedServerList(
-                    0,
-                    EpdgSelector.PROTO_FILTER_IPV4V6,
-                    EpdgSelector.SYSTEM_PREFERRED,
-                    isRoaming,
-                    true,
-                    network,
-                    null);
-        }
-
         private int getCurrentCellularRat() {
             TelephonyManager telephonyManager = mContext.getSystemService(TelephonyManager.class);
             telephonyManager =
@@ -1260,12 +1182,12 @@ public class IwlanDataService extends DataService {
          */
         @Override
         public void close() {
-            // TODO: call epdgtunnelmanager.releaseInstance or equivalent
             mIwlanDataService.removeDataServiceProvider(this);
             IwlanEventListener iwlanEventListener =
                     IwlanEventListener.getInstance(mContext, getSlotIndex());
-            iwlanEventListener.removeEventListener(getIwlanDataServiceHandler());
+            iwlanEventListener.removeEventListener(getHandler());
             iwlanEventListener.unregisterContentObserver();
+            mEpdgTunnelManager.close();
         }
 
         public void dump(FileDescriptor fd, PrintWriter pw, String[] args) {
@@ -1359,6 +1281,29 @@ public class IwlanDataService extends DataService {
             return Arrays.stream(nrAvailabilities)
                     .anyMatch(k -> k == CarrierConfigManager.CARRIER_NR_AVAILABILITY_SA);
         }
+
+        private void recordAndSendTunnelOpenedMetrics(OnOpenedMetrics openedMetricsData) {
+            MetricsAtom metricsAtom;
+            // Record setup result for the Metrics
+            metricsAtom = mMetricsAtomForApn.get(openedMetricsData.getApnName());
+            metricsAtom.setSetupRequestResult(DataServiceCallback.RESULT_SUCCESS);
+            metricsAtom.setIwlanError(IwlanError.NO_ERROR);
+            metricsAtom.setDataCallFailCause(DataFailCause.NONE);
+            metricsAtom.setHandoverFailureMode(DataCallResponse.HANDOVER_FAILURE_MODE_UNKNOWN);
+            metricsAtom.setRetryDurationMillis(0);
+            metricsAtom.setMessageId(IwlanStatsLog.IWLAN_SETUP_DATA_CALL_RESULT_REPORTED);
+            metricsAtom.setEpdgServerAddress(openedMetricsData.getEpdgServerAddress());
+            metricsAtom.setProcessingDurationMillis(
+                    (int) (System.currentTimeMillis() - mProcessingStartTime));
+            metricsAtom.setEpdgServerSelectionDurationMillis(
+                    openedMetricsData.getEpdgServerSelectionDuration());
+            metricsAtom.setIkeTunnelEstablishmentDurationMillis(
+                    openedMetricsData.getIkeTunnelEstablishmentDuration());
+            metricsAtom.setIsNetworkValidated(openedMetricsData.isNetworkValidated());
+
+            metricsAtom.sendMetricsData();
+            metricsAtom.setMessageId(MetricsAtom.INVALID_MESSAGE_ID);
+        }
     }
 
     private final class IwlanDataServiceHandler extends Handler {
@@ -1368,204 +1313,11 @@ public class IwlanDataService extends DataService {
         public void handleMessage(Message msg) {
             Log.d(TAG, "msg.what = " + eventToString(msg.what));
 
-            String apnName;
             IwlanDataServiceProvider iwlanDataServiceProvider;
-            IwlanDataServiceProvider.TunnelState tunnelState;
             DataServiceCallback callback;
-            int reason;
             int slotId;
-            int retryTimeMillis;
-            int errorCause;
-            MetricsAtom metricsAtom;
 
             switch (msg.what) {
-                case EVENT_TUNNEL_OPENED:
-                    TunnelOpenedData tunnelOpenedData = (TunnelOpenedData) msg.obj;
-                    iwlanDataServiceProvider = tunnelOpenedData.mIwlanDataServiceProvider;
-                    apnName = tunnelOpenedData.mApnName;
-                    TunnelLinkProperties tunnelLinkProperties =
-                            tunnelOpenedData.mTunnelLinkProperties;
-
-                    tunnelState = iwlanDataServiceProvider.mTunnelStateForApn.get(apnName);
-                    // tunnelstate should not be null, design violation.
-                    // if its null, we should crash and debug.
-                    tunnelState.setTunnelLinkProperties(tunnelLinkProperties);
-                    tunnelState.setState(IwlanDataServiceProvider.TunnelState.TUNNEL_UP);
-                    iwlanDataServiceProvider.mTunnelStats.reportTunnelSetupSuccess(
-                            apnName, tunnelState);
-
-                    iwlanDataServiceProvider.deliverCallback(
-                            IwlanDataServiceProvider.CALLBACK_TYPE_SETUP_DATACALL_COMPLETE,
-                            DataServiceCallback.RESULT_SUCCESS,
-                            tunnelState.getDataServiceCallback(),
-                            iwlanDataServiceProvider.apnTunnelStateToDataCallResponse(apnName));
-                    break;
-
-                case EVENT_TUNNEL_CLOSED:
-                    TunnelClosedData tunnelClosedData = (TunnelClosedData) msg.obj;
-                    iwlanDataServiceProvider = tunnelClosedData.mIwlanDataServiceProvider;
-                    apnName = tunnelClosedData.mApnName;
-                    IwlanError iwlanError = tunnelClosedData.mIwlanError;
-
-                    tunnelState = iwlanDataServiceProvider.mTunnelStateForApn.get(apnName);
-
-                    if (tunnelState == null) {
-                        // On a successful handover to EUTRAN, the NW may initiate an IKE DEL before
-                        // the UE initiates a deactivateDataCall(). There may be a race condition
-                        // where the deactivateDataCall() arrives immediately before
-                        // IwlanDataService receives EVENT_TUNNEL_CLOSED (and clears TunnelState).
-                        // Even though there is no tunnel, EpdgTunnelManager will still process the
-                        // bringdown request and send back an onClosed() to ensure state coherence.
-                        if (iwlanError.getErrorType() != IwlanError.TUNNEL_NOT_FOUND) {
-                            Log.w(
-                                    TAG,
-                                    "Tunnel state does not exist! Unexpected IwlanError: "
-                                            + iwlanError);
-                        }
-                        break;
-                    }
-
-                    if (tunnelState.hasPendingDeactivateDataCallData()) {
-                        // Iwlan delays handling EVENT_DEACTIVATE_DATA_CALL to give the network time
-                        // to release the PDN.  This allows for immediate response to Telephony if
-                        // the network releases the PDN before timeout. Otherwise, Telephony's PDN
-                        // state waits for Iwlan, blocking further actions on this PDN.
-                        cancelPendingDeactivationIfExists(
-                                tunnelState.getPendingDeactivateDataCallData());
-                    }
-
-                    iwlanDataServiceProvider.mTunnelStats.reportTunnelDown(apnName, tunnelState);
-                    iwlanDataServiceProvider.mTunnelStateForApn.remove(apnName);
-                    metricsAtom = iwlanDataServiceProvider.mMetricsAtomForApn.get(apnName);
-
-                    if (tunnelState.getState()
-                                    == IwlanDataServiceProvider.TunnelState.TUNNEL_IN_BRINGUP
-                            || tunnelState.getState()
-                                    == IwlanDataServiceProvider.TunnelState
-                                            .TUNNEL_IN_FORCE_CLEAN_WAS_IN_BRINGUP) {
-                        DataCallResponse.Builder respBuilder = new DataCallResponse.Builder();
-                        respBuilder
-                                .setId(apnName.hashCode())
-                                .setProtocolType(tunnelState.getRequestedProtocolType());
-
-                        if (iwlanDataServiceProvider.shouldRetryWithInitialAttachForHandoverRequest(
-                                apnName, tunnelState)) {
-                            respBuilder.setHandoverFailureMode(
-                                    DataCallResponse
-                                            .HANDOVER_FAILURE_MODE_NO_FALLBACK_RETRY_SETUP_NORMAL);
-                            metricsAtom.setHandoverFailureMode(
-                                    DataCallResponse
-                                            .HANDOVER_FAILURE_MODE_NO_FALLBACK_RETRY_SETUP_NORMAL);
-                        } else if (tunnelState.getIsHandover()) {
-                            respBuilder.setHandoverFailureMode(
-                                    DataCallResponse
-                                            .HANDOVER_FAILURE_MODE_NO_FALLBACK_RETRY_HANDOVER);
-                            metricsAtom.setHandoverFailureMode(
-                                    DataCallResponse
-                                            .HANDOVER_FAILURE_MODE_NO_FALLBACK_RETRY_HANDOVER);
-                        }
-
-                        errorCause =
-                                ErrorPolicyManager.getInstance(
-                                                mContext, iwlanDataServiceProvider.getSlotIndex())
-                                        .getDataFailCause(apnName);
-                        if (errorCause != DataFailCause.NONE) {
-                            respBuilder.setCause(errorCause);
-                            metricsAtom.setDataCallFailCause(errorCause);
-
-                            retryTimeMillis =
-                                    (int)
-                                            ErrorPolicyManager.getInstance(
-                                                            mContext,
-                                                            iwlanDataServiceProvider.getSlotIndex())
-                                                    .getRemainingRetryTimeMs(apnName);
-                            // TODO(b/343962773): Need to refactor into ErrorPolicyManager
-                            if (!tunnelState.getIsHandover()
-                                    && tunnelState.hasApnType(ApnSetting.TYPE_EMERGENCY)) {
-                                retryTimeMillis = DataCallResponse.RETRY_DURATION_UNDEFINED;
-                            }
-                            respBuilder.setRetryDurationMillis(retryTimeMillis);
-                            metricsAtom.setRetryDurationMillis(retryTimeMillis);
-                        } else {
-                            // TODO(b/265215349): Use a different DataFailCause for scenario where
-                            // tunnel in bringup is closed or force-closed without error.
-                            respBuilder.setCause(DataFailCause.IWLAN_NETWORK_FAILURE);
-                            metricsAtom.setDataCallFailCause(DataFailCause.IWLAN_NETWORK_FAILURE);
-                            respBuilder.setRetryDurationMillis(5000);
-                            metricsAtom.setRetryDurationMillis(5000);
-                        }
-
-                        // Record setup result for the Metrics
-                        metricsAtom.setSetupRequestResult(DataServiceCallback.RESULT_SUCCESS);
-                        metricsAtom.setIwlanError(iwlanError.getErrorType());
-                        metricsAtom.setIwlanErrorWrappedClassnameAndStack(iwlanError);
-                        metricsAtom.setMessageId(
-                                IwlanStatsLog.IWLAN_SETUP_DATA_CALL_RESULT_REPORTED);
-                        metricsAtom.setErrorCountOfSameCause(
-                                ErrorPolicyManager.getInstance(
-                                                mContext, iwlanDataServiceProvider.getSlotIndex())
-                                        .getLastErrorCountOfSameCause(apnName));
-
-                        iwlanDataServiceProvider.deliverCallback(
-                                IwlanDataServiceProvider.CALLBACK_TYPE_SETUP_DATACALL_COMPLETE,
-                                DataServiceCallback.RESULT_SUCCESS,
-                                tunnelState.getDataServiceCallback(),
-                                respBuilder.build());
-                        return;
-                    }
-
-                    // iwlan service triggered teardown
-                    if (tunnelState.getState()
-                            == IwlanDataServiceProvider.TunnelState.TUNNEL_IN_BRINGDOWN) {
-
-                        // IO exception happens when IKE library fails to retransmit requests.
-                        // This can happen for multiple reasons:
-                        // 1. Network disconnection due to wifi off.
-                        // 2. Epdg server does not respond.
-                        // 3. Socket send/receive fails.
-                        // Ignore this during tunnel bring down.
-                        if (iwlanError.getErrorType() != IwlanError.NO_ERROR
-                                && iwlanError.getErrorType()
-                                        != IwlanError.IKE_INTERNAL_IO_EXCEPTION) {
-                            Log.e(TAG, "Unexpected error during tunnel bring down: " + iwlanError);
-                        }
-
-                        iwlanDataServiceProvider.deliverCallback(
-                                IwlanDataServiceProvider.CALLBACK_TYPE_DEACTIVATE_DATACALL_COMPLETE,
-                                DataServiceCallback.RESULT_SUCCESS,
-                                tunnelState.getDataServiceCallback(),
-                                null);
-
-                        return;
-                    }
-
-                    // just update list of data calls. No way to send error up
-                    iwlanDataServiceProvider.notifyDataCallListChanged(
-                            iwlanDataServiceProvider.getCallList());
-
-                    // Report IwlanPdnDisconnectedReason due to the disconnection is neither for
-                    // SETUP_DATA_CALL nor DEACTIVATE_DATA_CALL request.
-                    metricsAtom.setDataCallFailCause(
-                            ErrorPolicyManager.getInstance(
-                                            mContext, iwlanDataServiceProvider.getSlotIndex())
-                                    .getDataFailCause(apnName));
-
-                    WifiManager wifiManager = mContext.getSystemService(WifiManager.class);
-                    if (wifiManager == null) {
-                        Log.e(TAG, "Could not find wifiManager");
-                        return;
-                    }
-
-                    WifiInfo wifiInfo = getWifiInfo(sNetworkCapabilities);
-                    if (wifiInfo == null) {
-                        Log.e(TAG, "wifiInfo is null");
-                        return;
-                    }
-
-                    metricsAtom.setWifiSignalValue(wifiInfo.getRssi());
-                    metricsAtom.setMessageId(IwlanStatsLog.IWLAN_PDN_DISCONNECTED_REASON_REPORTED);
-                    break;
-
                 case IwlanEventListener.CARRIER_CONFIG_CHANGED_EVENT:
                     iwlanDataServiceProvider =
                             (IwlanDataServiceProvider) getDataServiceProvider(msg.arg1);
@@ -1624,12 +1376,28 @@ public class IwlanDataService extends DataService {
                     }
                     break;
 
+                case IwlanEventListener.SCREEN_ON_EVENT:
+                    EpdgTunnelManager.getInstance(mContext, msg.arg1)
+                            .validateUnderlyingNetwork(
+                                    IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_SCREEN_ON);
+                    break;
+
                 case IwlanEventListener.CALL_STATE_CHANGED_EVENT:
                     iwlanDataServiceProvider =
                             (IwlanDataServiceProvider) getDataServiceProvider(msg.arg1);
 
                     int previousCallState = iwlanDataServiceProvider.mCallState;
                     int currentCallState = iwlanDataServiceProvider.mCallState = msg.arg2;
+                    boolean isCallInitiating =
+                            previousCallState == TelephonyManager.CALL_STATE_IDLE
+                                    && currentCallState == TelephonyManager.CALL_STATE_OFFHOOK;
+
+                    if (isCallInitiating) {
+                        int slotIndex = msg.arg1;
+                        EpdgTunnelManager.getInstance(mContext, slotIndex)
+                                .validateUnderlyingNetwork(
+                                        IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_MAKING_CALL);
+                    }
 
                     if (!IwlanCarrierConfig.getConfigBoolean(
                             mContext,
@@ -1659,186 +1427,6 @@ public class IwlanDataService extends DataService {
                     onPreferredNetworkTypeChanged(iwlanDataServiceProvider, allowedNetworkType);
                     break;
 
-                case EVENT_SETUP_DATA_CALL:
-                    SetupDataCallData setupDataCallData = (SetupDataCallData) msg.obj;
-                    int accessNetworkType = setupDataCallData.mAccessNetworkType;
-                    @NonNull DataProfile dataProfile = setupDataCallData.mDataProfile;
-                    boolean isRoaming = setupDataCallData.mIsRoaming;
-                    reason = setupDataCallData.mReason;
-                    LinkProperties linkProperties = setupDataCallData.mLinkProperties;
-                    @IntRange(from = 0, to = 15)
-                    int pduSessionId = setupDataCallData.mPduSessionId;
-                    callback = setupDataCallData.mCallback;
-                    iwlanDataServiceProvider = setupDataCallData.mIwlanDataServiceProvider;
-
-                    if ((accessNetworkType != AccessNetworkType.IWLAN)
-                            || (dataProfile == null)
-                            || (dataProfile.getApnSetting() == null)
-                            || (linkProperties == null
-                                    && reason == DataService.REQUEST_REASON_HANDOVER)) {
-
-                        iwlanDataServiceProvider.deliverCallback(
-                                IwlanDataServiceProvider.CALLBACK_TYPE_SETUP_DATACALL_COMPLETE,
-                                DataServiceCallback.RESULT_ERROR_INVALID_ARG,
-                                callback,
-                                null);
-                        return;
-                    }
-
-                    slotId = iwlanDataServiceProvider.getSlotIndex();
-                    boolean isCSTEnabled = IwlanHelper.isCrossSimCallingEnabled(mContext, slotId);
-                    boolean networkConnected =
-                            isNetworkConnected(isActiveDataOnOtherSub(slotId), isCSTEnabled);
-                    Log.d(
-                            TAG + "[" + slotId + "]",
-                            "isDds: "
-                                    + IwlanHelper.isDefaultDataSlot(mContext, slotId)
-                                    + ", isActiveDataOnOtherSub: "
-                                    + isActiveDataOnOtherSub(slotId)
-                                    + ", isCstEnabled: "
-                                    + isCSTEnabled
-                                    + ", transport: "
-                                    + sDefaultDataTransport);
-
-                    if (!networkConnected) {
-                        iwlanDataServiceProvider.deliverCallback(
-                                IwlanDataServiceProvider.CALLBACK_TYPE_SETUP_DATACALL_COMPLETE,
-                                5 /* DataServiceCallback.RESULT_ERROR_TEMPORARILY_UNAVAILABLE
-                                   */,
-                                callback,
-                                null);
-                        return;
-                    }
-
-                    // Update Network & LinkProperties to EpdgTunnelManager
-                    iwlanDataServiceProvider
-                            .getTunnelManager()
-                            .updateNetwork(sNetwork, sLinkProperties);
-                    Log.d(TAG, "Update Network for SetupDataCall request");
-
-                    tunnelState =
-                            iwlanDataServiceProvider.mTunnelStateForApn.get(
-                                    dataProfile.getApnSetting().getApnName());
-
-                    // Return the existing PDN if the pduSessionId is the same and the tunnel
-                    // state is TUNNEL_UP.
-                    if (tunnelState != null) {
-                        if (tunnelState.getPduSessionId() == pduSessionId
-                                && tunnelState.getState()
-                                        == IwlanDataServiceProvider.TunnelState.TUNNEL_UP) {
-                            Log.w(
-                                    TAG + "[" + slotId + "]",
-                                    "The tunnel for "
-                                            + dataProfile.getApnSetting().getApnName()
-                                            + " already exists.");
-                            iwlanDataServiceProvider.deliverCallback(
-                                    IwlanDataServiceProvider.CALLBACK_TYPE_SETUP_DATACALL_COMPLETE,
-                                    DataServiceCallback.RESULT_SUCCESS,
-                                    callback,
-                                    iwlanDataServiceProvider.apnTunnelStateToDataCallResponse(
-                                            dataProfile.getApnSetting().getApnName()));
-                        } else {
-                            Log.e(
-                                    TAG + "[" + slotId + "]",
-                                    "Force close the existing PDN. pduSessionId = "
-                                            + tunnelState.getPduSessionId()
-                                            + " Tunnel State = "
-                                            + tunnelState.getState());
-                            iwlanDataServiceProvider
-                                    .getTunnelManager()
-                                    .closeTunnel(
-                                            dataProfile.getApnSetting().getApnName(),
-                                            true /* forceClose */,
-                                            iwlanDataServiceProvider.getIwlanTunnelCallback(),
-                                            iwlanDataServiceProvider.getIwlanTunnelMetrics(),
-                                            BRINGDOWN_REASON_SERVICE_OUT_OF_SYNC);
-                            iwlanDataServiceProvider.deliverCallback(
-                                    IwlanDataServiceProvider.CALLBACK_TYPE_SETUP_DATACALL_COMPLETE,
-                                    5 /* DataServiceCallback
-                                      .RESULT_ERROR_TEMPORARILY_UNAVAILABLE */,
-                                    callback,
-                                    null);
-                        }
-                        return;
-                    }
-
-                    int apnTypeBitmask = dataProfile.getApnSetting().getApnTypeBitmask();
-                    boolean isIms = hasApnTypes(apnTypeBitmask, ApnSetting.TYPE_IMS);
-                    boolean isEmergency = hasApnTypes(apnTypeBitmask, ApnSetting.TYPE_EMERGENCY);
-
-                    boolean isDataCallSetupWithN1 =
-                            iwlanDataServiceProvider.needIncludeN1ModeCapability();
-
-                    // Override N1_MODE_CAPABILITY exclusion only for Emergency PDN due to carrier
-                    // network limitations
-                    if (IwlanCarrierConfig.getConfigBoolean(
-                                    mContext,
-                                    slotId,
-                                    IwlanCarrierConfig
-                                            .KEY_N1_MODE_EXCLUSION_FOR_EMERGENCY_SESSION_BOOL)
-                            && isEmergency) {
-                        isDataCallSetupWithN1 = false;
-                    }
-
-                    TunnelSetupRequest.Builder tunnelReqBuilder =
-                            TunnelSetupRequest.builder()
-                                    .setApnName(dataProfile.getApnSetting().getApnName())
-                                    .setIsRoaming(isRoaming)
-                                    .setPduSessionId(
-                                            isDataCallSetupWithN1
-                                                    ? pduSessionId
-                                                    : PDU_SESSION_ID_UNSET)
-                                    .setApnIpProtocol(
-                                            isRoaming
-                                                    ? dataProfile
-                                                            .getApnSetting()
-                                                            .getRoamingProtocol()
-                                                    : dataProfile.getApnSetting().getProtocol())
-                                    .setRequestPcscf(isIms || isEmergency)
-                                    .setIsEmergency(isEmergency);
-
-                    if (reason == DataService.REQUEST_REASON_HANDOVER) {
-                        // for now assume that, at max,  only one address of each type (v4/v6).
-                        // TODO: Check if multiple ips can be sent in ike tunnel setup
-                        for (LinkAddress lAddr : linkProperties.getLinkAddresses()) {
-                            if (lAddr.isIpv4()) {
-                                tunnelReqBuilder.setSrcIpv4Address(lAddr.getAddress());
-                            } else if (lAddr.isIpv6()) {
-                                tunnelReqBuilder.setSrcIpv6Address(lAddr.getAddress());
-                                tunnelReqBuilder.setSrcIpv6AddressPrefixLength(
-                                        lAddr.getPrefixLength());
-                            }
-                        }
-                    }
-
-                    iwlanDataServiceProvider.setTunnelState(
-                            dataProfile,
-                            callback,
-                            IwlanDataServiceProvider.TunnelState.TUNNEL_IN_BRINGUP,
-                            null,
-                            (reason == DataService.REQUEST_REASON_HANDOVER),
-                            pduSessionId,
-                            isIms || isEmergency,
-                            isDataCallSetupWithN1);
-
-                    boolean result =
-                            iwlanDataServiceProvider
-                                    .getTunnelManager()
-                                    .bringUpTunnel(
-                                            tunnelReqBuilder.build(),
-                                            iwlanDataServiceProvider.getIwlanTunnelCallback(),
-                                            iwlanDataServiceProvider.getIwlanTunnelMetrics());
-                    Log.d(TAG + "[" + slotId + "]", "bringup Tunnel with result:" + result);
-                    if (!result) {
-                        iwlanDataServiceProvider.deliverCallback(
-                                IwlanDataServiceProvider.CALLBACK_TYPE_SETUP_DATACALL_COMPLETE,
-                                DataServiceCallback.RESULT_ERROR_INVALID_ARG,
-                                callback,
-                                null);
-                        return;
-                    }
-                    break;
-
                 case EVENT_DEACTIVATE_DATA_CALL:
                     handleDeactivateDataCall((DeactivateDataCallData) msg.obj);
                     break;
@@ -1884,62 +1472,6 @@ public class IwlanDataService extends DataService {
                     }
                     break;
 
-                case EVENT_TUNNEL_OPENED_METRICS:
-                    OnOpenedMetrics openedMetricsData = (OnOpenedMetrics) msg.obj;
-                    iwlanDataServiceProvider = openedMetricsData.getIwlanDataServiceProvider();
-                    apnName = openedMetricsData.getApnName();
-
-                    // Record setup result for the Metrics
-                    metricsAtom = iwlanDataServiceProvider.mMetricsAtomForApn.get(apnName);
-                    metricsAtom.setSetupRequestResult(DataServiceCallback.RESULT_SUCCESS);
-                    metricsAtom.setIwlanError(IwlanError.NO_ERROR);
-                    metricsAtom.setDataCallFailCause(DataFailCause.NONE);
-                    metricsAtom.setHandoverFailureMode(-1);
-                    metricsAtom.setRetryDurationMillis(0);
-                    metricsAtom.setMessageId(IwlanStatsLog.IWLAN_SETUP_DATA_CALL_RESULT_REPORTED);
-                    metricsAtom.setEpdgServerAddress(openedMetricsData.getEpdgServerAddress());
-                    metricsAtom.setProcessingDurationMillis(
-                            (int)
-                                    (System.currentTimeMillis()
-                                            - iwlanDataServiceProvider.mProcessingStartTime));
-                    metricsAtom.setEpdgServerSelectionDurationMillis(
-                            openedMetricsData.getEpdgServerSelectionDuration());
-                    metricsAtom.setIkeTunnelEstablishmentDurationMillis(
-                            openedMetricsData.getIkeTunnelEstablishmentDuration());
-                    metricsAtom.setIsNetworkValidated(openedMetricsData.isNetworkValidated());
-
-                    metricsAtom.sendMetricsData();
-                    metricsAtom.setMessageId(MetricsAtom.INVALID_MESSAGE_ID);
-                    break;
-
-                case EVENT_TUNNEL_CLOSED_METRICS:
-                    OnClosedMetrics closedMetricsData = (OnClosedMetrics) msg.obj;
-                    iwlanDataServiceProvider = closedMetricsData.getIwlanDataServiceProvider();
-                    apnName = closedMetricsData.getApnName();
-
-                    metricsAtom = iwlanDataServiceProvider.mMetricsAtomForApn.get(apnName);
-                    if (metricsAtom == null) {
-                        Log.w(TAG, "EVENT_TUNNEL_CLOSED_METRICS: MetricsAtom is null!");
-                        break;
-                    }
-                    metricsAtom.setEpdgServerAddress(closedMetricsData.getEpdgServerAddress());
-                    metricsAtom.setProcessingDurationMillis(
-                            iwlanDataServiceProvider.mProcessingStartTime > 0
-                                    ? (int)
-                                            (System.currentTimeMillis()
-                                                    - iwlanDataServiceProvider.mProcessingStartTime)
-                                    : 0);
-                    metricsAtom.setEpdgServerSelectionDurationMillis(
-                            closedMetricsData.getEpdgServerSelectionDuration());
-                    metricsAtom.setIkeTunnelEstablishmentDurationMillis(
-                            closedMetricsData.getIkeTunnelEstablishmentDuration());
-                    metricsAtom.setIsNetworkValidated(closedMetricsData.isNetworkValidated());
-
-                    metricsAtom.sendMetricsData();
-                    metricsAtom.setMessageId(MetricsAtom.INVALID_MESSAGE_ID);
-                    iwlanDataServiceProvider.mMetricsAtomForApn.remove(apnName);
-                    break;
-
                 case EVENT_ON_LIVENESS_STATUS_CHANGED:
                     handleLivenessStatusChange((TunnelValidationStatusData) msg.obj);
                     break;
@@ -1953,173 +1485,11 @@ public class IwlanDataService extends DataService {
             }
         }
 
-        public void handleDeactivateDataCall(DeactivateDataCallData data) {
-            handleDeactivateDataCall(data, false);
-        }
-
-        public void handleDeactivateDataCallWithDelay(DeactivateDataCallData data) {
-            handleDeactivateDataCall(data, true);
-        }
-
-        public void handleDeactivateDataCall(DeactivateDataCallData data, boolean isWithDelay) {
-            IwlanDataServiceProvider serviceProvider = data.mIwlanDataServiceProvider;
-            String matchingApn = findMatchingApn(serviceProvider, data.mCid);
-
-            if (matchingApn == null) {
-                deliverDeactivationError(serviceProvider, data.mCallback);
-                return;
-            }
-
-            if (isWithDelay) {
-                Log.d(TAG, "Delaying deactivation for APN: " + matchingApn);
-                scheduleDelayedDeactivateDataCall(serviceProvider, data, matchingApn);
-                return;
-            }
-            Log.d(TAG, "Processing deactivation for APN: " + matchingApn);
-            processDeactivateDataCall(serviceProvider, data, matchingApn);
-        }
-
-        private void handleNetworkValidationRequest(NetworkValidationInfo networkValidationInfo) {
-            IwlanDataServiceProvider iwlanDataServiceProvider =
-                    networkValidationInfo.mIwlanDataServiceProvider;
-            int cid = networkValidationInfo.mCid;
-            Executor executor = networkValidationInfo.mExecutor;
-            Consumer<Integer> resultCodeCallback = networkValidationInfo.mResultCodeCallback;
-            IwlanDataServiceProvider.TunnelState tunnelState;
-
-            String apnName = findMatchingApn(iwlanDataServiceProvider, cid);
-            int resultCode;
-            if (apnName == null) {
-                Log.w(TAG, "no matching APN name found for network validation.");
-                resultCode = DataServiceCallback.RESULT_ERROR_UNSUPPORTED;
-            } else {
-                EpdgTunnelManager epdgTunnelManager = iwlanDataServiceProvider.getTunnelManager();
-                epdgTunnelManager.requestNetworkValidationForApn(apnName);
-                resultCode = DataServiceCallback.RESULT_SUCCESS;
-                tunnelState = iwlanDataServiceProvider.mTunnelStateForApn.get(apnName);
-                if (tunnelState == null) {
-                    Log.w(TAG, "EVENT_REQUEST_NETWORK_VALIDATION: tunnel state is null.");
-                } else {
-                    tunnelState.setNetworkValidationStatus(
-                            PreciseDataConnectionState.NETWORK_VALIDATION_IN_PROGRESS);
-                }
-            }
-            executor.execute(() -> resultCodeCallback.accept(resultCode));
-        }
-
-        private void handleLivenessStatusChange(TunnelValidationStatusData validationStatusData) {
-            IwlanDataServiceProvider iwlanDataServiceProvider =
-                    validationStatusData.mIwlanDataServiceProvider;
-            String apnName = validationStatusData.mApnName;
-            IwlanDataServiceProvider.TunnelState tunnelState =
-                    iwlanDataServiceProvider.mTunnelStateForApn.get(apnName);
-            if (tunnelState == null) {
-                Log.w(TAG, "EVENT_ON_LIVENESS_STATUS_CHANGED: tunnel state is null.");
-                return;
-            }
-            tunnelState.setNetworkValidationStatus(validationStatusData.mStatus);
-            iwlanDataServiceProvider.notifyDataCallListChanged(
-                    iwlanDataServiceProvider.getCallList());
-        }
-
-        private String findMatchingApn(IwlanDataServiceProvider serviceProvider, int cid) {
-            return serviceProvider.mTunnelStateForApn.keySet().stream()
-                    .filter(apn -> apn.hashCode() == cid)
-                    .findFirst()
-                    .orElse(null);
-        }
-
-        private void deliverDeactivationError(
-                IwlanDataServiceProvider serviceProvider, DataServiceCallback callback) {
-            serviceProvider.deliverCallback(
-                    IwlanDataServiceProvider.CALLBACK_TYPE_DEACTIVATE_DATACALL_COMPLETE,
-                    DataServiceCallback.RESULT_ERROR_INVALID_ARG,
-                    callback,
-                    null);
-        }
-
-        private void scheduleDelayedDeactivateDataCall(
-                IwlanDataServiceProvider serviceProvider,
-                DeactivateDataCallData data,
-                String matchingApn) {
-            IwlanDataServiceProvider.TunnelState tunnelState =
-                    serviceProvider.mTunnelStateForApn.get(matchingApn);
-            tunnelState.setPendingDeactivateDataCallData(data);
-            tunnelState.setState(IwlanDataServiceProvider.TunnelState.TUNNEL_IN_BRINGDOWN);
-            Handler handler = getIwlanDataServiceHandler();
-            handler.sendMessageDelayed(
-                    handler.obtainMessage(EVENT_DEACTIVATE_DATA_CALL, data),
-                    data.mDelayTimeSeconds * 1000L);
-        }
-
-        private void processDeactivateDataCall(
-                IwlanDataServiceProvider serviceProvider,
-                DeactivateDataCallData data,
-                String matchingApn) {
-            int slotId = serviceProvider.getSlotIndex();
-            boolean isNetworkLost =
-                    !isNetworkConnected(
-                            isActiveDataOnOtherSub(slotId),
-                            IwlanHelper.isCrossSimCallingEnabled(mContext, slotId));
-            boolean isHandoverSuccessful = (data.mReason == REQUEST_REASON_HANDOVER);
-
-            IwlanDataServiceProvider.TunnelState tunnelState =
-                    serviceProvider.mTunnelStateForApn.get(matchingApn);
-            tunnelState.setState(IwlanDataServiceProvider.TunnelState.TUNNEL_IN_BRINGDOWN);
-            tunnelState.setDataServiceCallback(data.mCallback);
-
-            serviceProvider
-                    .getTunnelManager()
-                    .closeTunnel(
-                            matchingApn,
-                            isNetworkLost || isHandoverSuccessful, /* forceClose */
-                            serviceProvider.getIwlanTunnelCallback(),
-                            serviceProvider.getIwlanTunnelMetrics(),
-                            BRINGDOWN_REASON_DEACTIVATE_DATA_CALL);
-        }
-
-        private void cancelPendingDeactivationIfExists(
-                DeactivateDataCallData deactivateDataCallData) {
-            Handler handler = getIwlanDataServiceHandler();
-            if (handler.hasMessages(EVENT_DEACTIVATE_DATA_CALL, deactivateDataCallData)) {
-                // Remove any existing deactivation messages and request a new one in the front
-                handler.removeMessages(EVENT_DEACTIVATE_DATA_CALL, deactivateDataCallData);
-            }
-        }
-
         IwlanDataServiceHandler(Looper looper) {
             super(looper);
         }
     }
 
-    private static final class TunnelOpenedData {
-        final String mApnName;
-        final TunnelLinkProperties mTunnelLinkProperties;
-        final IwlanDataServiceProvider mIwlanDataServiceProvider;
-
-        private TunnelOpenedData(
-                String apnName,
-                TunnelLinkProperties tunnelLinkProperties,
-                IwlanDataServiceProvider dsp) {
-            mApnName = apnName;
-            mTunnelLinkProperties = tunnelLinkProperties;
-            mIwlanDataServiceProvider = dsp;
-        }
-    }
-
-    private static final class TunnelClosedData {
-        final String mApnName;
-        final IwlanError mIwlanError;
-        final IwlanDataServiceProvider mIwlanDataServiceProvider;
-
-        private TunnelClosedData(
-                String apnName, IwlanError iwlanError, IwlanDataServiceProvider dsp) {
-            mApnName = apnName;
-            mIwlanError = iwlanError;
-            mIwlanDataServiceProvider = dsp;
-        }
-    }
-
     private static final class TunnelValidationStatusData {
         final String mApnName;
         final int mStatus;
@@ -2148,51 +1518,6 @@ public class IwlanDataService extends DataService {
         }
     }
 
-    private static final class SetupDataCallData {
-        final int mAccessNetworkType;
-        @NonNull final DataProfile mDataProfile;
-        final boolean mIsRoaming;
-        final boolean mAllowRoaming;
-        final int mReason;
-        @Nullable final LinkProperties mLinkProperties;
-
-        @IntRange(from = 0, to = 15)
-        final int mPduSessionId;
-
-        @Nullable final NetworkSliceInfo mSliceInfo;
-        @Nullable final TrafficDescriptor mTrafficDescriptor;
-        final boolean mMatchAllRuleAllowed;
-        @NonNull final DataServiceCallback mCallback;
-        final IwlanDataServiceProvider mIwlanDataServiceProvider;
-
-        private SetupDataCallData(
-                int accessNetworkType,
-                DataProfile dataProfile,
-                boolean isRoaming,
-                boolean allowRoaming,
-                int reason,
-                LinkProperties linkProperties,
-                int pduSessionId,
-                NetworkSliceInfo sliceInfo,
-                TrafficDescriptor trafficDescriptor,
-                boolean matchAllRuleAllowed,
-                DataServiceCallback callback,
-                IwlanDataServiceProvider dsp) {
-            mAccessNetworkType = accessNetworkType;
-            mDataProfile = dataProfile;
-            mIsRoaming = isRoaming;
-            mAllowRoaming = allowRoaming;
-            mReason = reason;
-            mLinkProperties = linkProperties;
-            mPduSessionId = pduSessionId;
-            mSliceInfo = sliceInfo;
-            mTrafficDescriptor = trafficDescriptor;
-            mMatchAllRuleAllowed = matchAllRuleAllowed;
-            mCallback = callback;
-            mIwlanDataServiceProvider = dsp;
-        }
-    }
-
     private static final class DeactivateDataCallData {
         final int mCid;
         final int mReason;
@@ -2377,25 +1702,19 @@ public class IwlanDataService extends DataService {
             mNetworkMonitorCallback = new IwlanNetworkMonitorCallback();
             if (connectivityManager != null) {
                 connectivityManager.registerSystemDefaultNetworkCallback(
-                        mNetworkMonitorCallback, getIwlanDataServiceHandler());
+                        mNetworkMonitorCallback, getHandler());
             }
             Log.d(TAG, "Registered with Connectivity Service");
         }
 
         IwlanDataServiceProvider dp = new IwlanDataServiceProvider(slotIndex, this);
 
-        getIwlanDataServiceHandler()
-                .sendMessage(
-                        getIwlanDataServiceHandler()
-                                .obtainMessage(EVENT_ADD_DATA_SERVICE_PROVIDER, dp));
+        getHandler().obtainMessage(EVENT_ADD_DATA_SERVICE_PROVIDER, dp).sendToTarget();
         return dp;
     }
 
     public void removeDataServiceProvider(IwlanDataServiceProvider dp) {
-        getIwlanDataServiceHandler()
-                .sendMessage(
-                        getIwlanDataServiceHandler()
-                                .obtainMessage(EVENT_REMOVE_DATA_SERVICE_PROVIDER, dp));
+        getHandler().obtainMessage(EVENT_REMOVE_DATA_SERVICE_PROVIDER, dp).sendToTarget();
     }
 
     @VisibleForTesting
@@ -2429,67 +1748,44 @@ public class IwlanDataService extends DataService {
 
     @VisibleForTesting
     @NonNull
-    Handler getIwlanDataServiceHandler() {
-        if (mIwlanDataServiceHandler == null) {
-            mIwlanDataServiceHandler = new IwlanDataServiceHandler(getLooper());
+    Handler getHandler() {
+        if (mHandler == null) {
+            mHandler = new IwlanDataServiceHandler(getLooper());
         }
-        return mIwlanDataServiceHandler;
+        return mHandler;
     }
 
     @VisibleForTesting
     Looper getLooper() {
-        mIwlanDataServiceHandlerThread = new HandlerThread("IwlanDataServiceThread");
-        mIwlanDataServiceHandlerThread.start();
-        return mIwlanDataServiceHandlerThread.getLooper();
+        mHandlerThread = new HandlerThread("IwlanDataServiceThread");
+        mHandlerThread.start();
+        return mHandlerThread.getLooper();
     }
 
     private static String eventToString(int event) {
-        switch (event) {
-            case EVENT_TUNNEL_OPENED:
-                return "EVENT_TUNNEL_OPENED";
-            case EVENT_TUNNEL_CLOSED:
-                return "EVENT_TUNNEL_CLOSED";
-            case EVENT_SETUP_DATA_CALL:
-                return "EVENT_SETUP_DATA_CALL";
-            case EVENT_DEACTIVATE_DATA_CALL:
-                return "EVENT_DEACTIVATE_DATA_CALL";
-            case EVENT_DATA_CALL_LIST_REQUEST:
-                return "EVENT_DATA_CALL_LIST_REQUEST";
-            case EVENT_FORCE_CLOSE_TUNNEL:
-                return "EVENT_FORCE_CLOSE_TUNNEL";
-            case EVENT_ADD_DATA_SERVICE_PROVIDER:
-                return "EVENT_ADD_DATA_SERVICE_PROVIDER";
-            case EVENT_REMOVE_DATA_SERVICE_PROVIDER:
-                return "EVENT_REMOVE_DATA_SERVICE_PROVIDER";
-            case IwlanEventListener.CARRIER_CONFIG_CHANGED_EVENT:
-                return "CARRIER_CONFIG_CHANGED_EVENT";
-            case IwlanEventListener.CARRIER_CONFIG_UNKNOWN_CARRIER_EVENT:
-                return "CARRIER_CONFIG_UNKNOWN_CARRIER_EVENT";
-            case IwlanEventListener.WIFI_CALLING_ENABLE_EVENT:
-                return "WIFI_CALLING_ENABLE_EVENT";
-            case IwlanEventListener.WIFI_CALLING_DISABLE_EVENT:
-                return "WIFI_CALLING_DISABLE_EVENT";
-            case IwlanEventListener.CROSS_SIM_CALLING_ENABLE_EVENT:
-                return "CROSS_SIM_CALLING_ENABLE_EVENT";
-            case IwlanEventListener.CELLINFO_CHANGED_EVENT:
-                return "CELLINFO_CHANGED_EVENT";
-            case EVENT_TUNNEL_OPENED_METRICS:
-                return "EVENT_TUNNEL_OPENED_METRICS";
-            case EVENT_TUNNEL_CLOSED_METRICS:
-                return "EVENT_TUNNEL_CLOSED_METRICS";
-            case EVENT_DEACTIVATE_DATA_CALL_WITH_DELAY:
-                return "EVENT_DEACTIVATE_DATA_CALL_WITH_DELAY";
-            case IwlanEventListener.CALL_STATE_CHANGED_EVENT:
-                return "CALL_STATE_CHANGED_EVENT";
-            case IwlanEventListener.PREFERRED_NETWORK_TYPE_CHANGED_EVENT:
-                return "PREFERRED_NETWORK_TYPE_CHANGED_EVENT";
-            case EVENT_ON_LIVENESS_STATUS_CHANGED:
-                return "EVENT_ON_LIVENESS_STATUS_CHANGED";
-            case EVENT_REQUEST_NETWORK_VALIDATION:
-                return "EVENT_REQUEST_NETWORK_VALIDATION";
-            default:
-                return "Unknown(" + event + ")";
-        }
+        return switch (event) {
+            case EVENT_DEACTIVATE_DATA_CALL -> "EVENT_DEACTIVATE_DATA_CALL";
+            case EVENT_DATA_CALL_LIST_REQUEST -> "EVENT_DATA_CALL_LIST_REQUEST";
+            case EVENT_FORCE_CLOSE_TUNNEL -> "EVENT_FORCE_CLOSE_TUNNEL";
+            case EVENT_ADD_DATA_SERVICE_PROVIDER -> "EVENT_ADD_DATA_SERVICE_PROVIDER";
+            case EVENT_REMOVE_DATA_SERVICE_PROVIDER -> "EVENT_REMOVE_DATA_SERVICE_PROVIDER";
+            case IwlanEventListener.CARRIER_CONFIG_CHANGED_EVENT -> "CARRIER_CONFIG_CHANGED_EVENT";
+            case IwlanEventListener.CARRIER_CONFIG_UNKNOWN_CARRIER_EVENT ->
+                    "CARRIER_CONFIG_UNKNOWN_CARRIER_EVENT";
+            case IwlanEventListener.WIFI_CALLING_ENABLE_EVENT -> "WIFI_CALLING_ENABLE_EVENT";
+            case IwlanEventListener.WIFI_CALLING_DISABLE_EVENT -> "WIFI_CALLING_DISABLE_EVENT";
+            case IwlanEventListener.CROSS_SIM_CALLING_ENABLE_EVENT ->
+                    "CROSS_SIM_CALLING_ENABLE_EVENT";
+            case IwlanEventListener.CELLINFO_CHANGED_EVENT -> "CELLINFO_CHANGED_EVENT";
+            case EVENT_DEACTIVATE_DATA_CALL_WITH_DELAY -> "EVENT_DEACTIVATE_DATA_CALL_WITH_DELAY";
+            case IwlanEventListener.CALL_STATE_CHANGED_EVENT -> "CALL_STATE_CHANGED_EVENT";
+            case IwlanEventListener.PREFERRED_NETWORK_TYPE_CHANGED_EVENT ->
+                    "PREFERRED_NETWORK_TYPE_CHANGED_EVENT";
+            case IwlanEventListener.SCREEN_ON_EVENT -> "SCREEN_ON_EVENT";
+            case EVENT_ON_LIVENESS_STATUS_CHANGED -> "EVENT_ON_LIVENESS_STATUS_CHANGED";
+            case EVENT_REQUEST_NETWORK_VALIDATION -> "EVENT_REQUEST_NETWORK_VALIDATION";
+            default -> "Unknown(" + event + ")";
+        };
     }
 
     private void initAllowedNetworkType() {
@@ -2552,26 +1848,505 @@ public class IwlanDataService extends DataService {
     @Override
     public boolean onUnbind(Intent intent) {
         Log.d(TAG, "IwlanDataService onUnbind");
-        getIwlanDataServiceHandler()
-                .sendMessage(getIwlanDataServiceHandler().obtainMessage(EVENT_FORCE_CLOSE_TUNNEL));
+        getHandler().obtainMessage(EVENT_FORCE_CLOSE_TUNNEL).sendToTarget();
         return super.onUnbind(intent);
     }
 
-    private String requestReasonToString(int reason) {
-        switch (reason) {
-            case DataService.REQUEST_REASON_UNKNOWN:
-                return "UNKNOWN";
-            case DataService.REQUEST_REASON_NORMAL:
-                return "NORMAL";
-            case DataService.REQUEST_REASON_SHUTDOWN:
-                return "SHUTDOWN";
-            case DataService.REQUEST_REASON_HANDOVER:
-                return "HANDOVER";
-            default:
-                return "UNKNOWN(" + reason + ")";
+    private boolean postToHandler(Runnable runnable) {
+        return mHandler.post(runnable);
+    }
+
+    private void handleTunnelOpened(
+            String apnName,
+            TunnelLinkProperties tunnelLinkProperties,
+            IwlanDataServiceProvider iwlanDataServiceProvider,
+            OnOpenedMetrics onOpenedMetrics) {
+        Log.d(
+                iwlanDataServiceProvider.SUB_TAG,
+                "Tunnel opened! APN: " + apnName + ", linkProperties: " + tunnelLinkProperties);
+        IwlanDataServiceProvider.TunnelState tunnelState =
+                iwlanDataServiceProvider.mTunnelStateForApn.get(apnName);
+        // tunnelstate should not be null, design violation.
+        // if its null, we should crash and debug.
+        tunnelState.setTunnelLinkProperties(tunnelLinkProperties);
+        tunnelState.setState(IwlanDataServiceProvider.TunnelState.TUNNEL_UP);
+        iwlanDataServiceProvider.mTunnelStats.reportTunnelSetupSuccess(apnName, tunnelState);
+
+        iwlanDataServiceProvider.recordAndSendTunnelOpenedMetrics(onOpenedMetrics);
+
+        iwlanDataServiceProvider.deliverCallback(
+                IwlanDataServiceProvider.CALLBACK_TYPE_SETUP_DATACALL_COMPLETE,
+                DataServiceCallback.RESULT_SUCCESS,
+                tunnelState.getDataServiceCallback(),
+                iwlanDataServiceProvider.apnTunnelStateToDataCallResponse(apnName));
+    }
+
+    private void handleTunnelClosed(
+            String apnName,
+            IwlanError iwlanError,
+            IwlanDataServiceProvider iwlanDataServiceProvider,
+            OnClosedMetrics onClosedMetrics) {
+        IwlanDataServiceProvider.TunnelState tunnelState =
+                iwlanDataServiceProvider.mTunnelStateForApn.get(apnName);
+
+        if (tunnelState == null) {
+            // On a successful handover to EUTRAN, the NW may initiate an IKE DEL before
+            // the UE initiates a deactivateDataCall(). There may be a race condition
+            // where the deactivateDataCall() arrives immediately before
+            // IwlanDataService receives EVENT_TUNNEL_CLOSED (and clears TunnelState).
+            // Even though there is no tunnel, EpdgTunnelManager will still process the
+            // bringdown request and send back an onClosed() to ensure state coherence.
+            if (iwlanError.getErrorType() != IwlanError.TUNNEL_NOT_FOUND) {
+                Log.w(TAG, "Tunnel state does not exist! Unexpected IwlanError: " + iwlanError);
+            }
+            return;
+        }
+
+        if (tunnelState.hasPendingDeactivateDataCallData()) {
+            // Iwlan delays handling EVENT_DEACTIVATE_DATA_CALL to give the network time
+            // to release the PDN.  This allows for immediate response to Telephony if
+            // the network releases the PDN before timeout. Otherwise, Telephony's PDN
+            // state waits for Iwlan, blocking further actions on this PDN.
+            DeactivateDataCallData deactivateDataCallData =
+                    tunnelState.getPendingDeactivateDataCallData();
+
+            Handler handler = getHandler();
+            if (handler.hasMessages(EVENT_DEACTIVATE_DATA_CALL, deactivateDataCallData)) {
+                // Remove any existing deactivation messages and request a new one in the front
+                handler.removeMessages(EVENT_DEACTIVATE_DATA_CALL, deactivateDataCallData);
+            }
+        }
+
+        iwlanDataServiceProvider.mTunnelStats.reportTunnelDown(apnName, tunnelState);
+        iwlanDataServiceProvider.mTunnelStateForApn.remove(apnName);
+        // TODO(b/358152549): extract all metricsAtom handling into a method
+        MetricsAtom metricsAtom = iwlanDataServiceProvider.mMetricsAtomForApn.get(apnName);
+
+        if (tunnelState.getState() == IwlanDataServiceProvider.TunnelState.TUNNEL_IN_BRINGUP
+                || tunnelState.getState()
+                        == IwlanDataServiceProvider.TunnelState
+                                .TUNNEL_IN_FORCE_CLEAN_WAS_IN_BRINGUP) {
+            DataCallResponse.Builder respBuilder = new DataCallResponse.Builder();
+            respBuilder
+                    .setId(apnName.hashCode())
+                    .setProtocolType(tunnelState.getRequestedProtocolType());
+
+            if (iwlanDataServiceProvider.shouldRetryWithInitialAttachForHandoverRequest(
+                    apnName, tunnelState)) {
+                respBuilder.setHandoverFailureMode(
+                        DataCallResponse.HANDOVER_FAILURE_MODE_NO_FALLBACK_RETRY_SETUP_NORMAL);
+                metricsAtom.setHandoverFailureMode(
+                        DataCallResponse.HANDOVER_FAILURE_MODE_NO_FALLBACK_RETRY_SETUP_NORMAL);
+            } else if (tunnelState.getIsHandover()) {
+                respBuilder.setHandoverFailureMode(
+                        DataCallResponse.HANDOVER_FAILURE_MODE_NO_FALLBACK_RETRY_HANDOVER);
+                metricsAtom.setHandoverFailureMode(
+                        DataCallResponse.HANDOVER_FAILURE_MODE_NO_FALLBACK_RETRY_HANDOVER);
+            }
+
+            int errorCause =
+                    ErrorPolicyManager.getInstance(
+                                    mContext, iwlanDataServiceProvider.getSlotIndex())
+                            .getDataFailCause(apnName);
+            if (errorCause != DataFailCause.NONE) {
+                respBuilder.setCause(errorCause);
+                metricsAtom.setDataCallFailCause(errorCause);
+
+                int retryTimeMillis =
+                        (int)
+                                ErrorPolicyManager.getInstance(
+                                                mContext, iwlanDataServiceProvider.getSlotIndex())
+                                        .getRemainingRetryTimeMs(apnName);
+                // TODO(b/343962773): Need to refactor into ErrorPolicyManager
+                if (!tunnelState.getIsHandover()
+                        && tunnelState.hasApnType(ApnSetting.TYPE_EMERGENCY)) {
+                    retryTimeMillis = DataCallResponse.RETRY_DURATION_UNDEFINED;
+                }
+                respBuilder.setRetryDurationMillis(retryTimeMillis);
+                metricsAtom.setRetryDurationMillis(retryTimeMillis);
+            } else {
+                // TODO(b/265215349): Use a different DataFailCause for scenario where
+                // tunnel in bringup is closed or force-closed without error.
+                respBuilder.setCause(DataFailCause.IWLAN_NETWORK_FAILURE);
+                metricsAtom.setDataCallFailCause(DataFailCause.IWLAN_NETWORK_FAILURE);
+                respBuilder.setRetryDurationMillis(5000);
+                metricsAtom.setRetryDurationMillis(5000);
+            }
+
+            // Record setup result for the Metrics
+            metricsAtom.setSetupRequestResult(DataServiceCallback.RESULT_SUCCESS);
+            metricsAtom.setIwlanError(iwlanError.getErrorType());
+            metricsAtom.setIwlanErrorWrappedClassnameAndStack(iwlanError);
+            metricsAtom.setMessageId(IwlanStatsLog.IWLAN_SETUP_DATA_CALL_RESULT_REPORTED);
+            metricsAtom.setErrorCountOfSameCause(
+                    ErrorPolicyManager.getInstance(
+                                    mContext, iwlanDataServiceProvider.getSlotIndex())
+                            .getLastErrorCountOfSameCause(apnName));
+
+            metricsAtom.setEpdgServerAddress(onClosedMetrics.getEpdgServerAddress());
+            metricsAtom.setProcessingDurationMillis(
+                    iwlanDataServiceProvider.mProcessingStartTime > 0
+                            ? (int)
+                                    (System.currentTimeMillis()
+                                            - iwlanDataServiceProvider.mProcessingStartTime)
+                            : 0);
+            metricsAtom.setEpdgServerSelectionDurationMillis(
+                    onClosedMetrics.getEpdgServerSelectionDuration());
+            metricsAtom.setIkeTunnelEstablishmentDurationMillis(
+                    onClosedMetrics.getIkeTunnelEstablishmentDuration());
+            metricsAtom.setIsNetworkValidated(onClosedMetrics.isNetworkValidated());
+
+            metricsAtom.sendMetricsData();
+            metricsAtom.setMessageId(MetricsAtom.INVALID_MESSAGE_ID);
+            iwlanDataServiceProvider.mMetricsAtomForApn.remove(apnName);
+
+            iwlanDataServiceProvider.deliverCallback(
+                    IwlanDataServiceProvider.CALLBACK_TYPE_SETUP_DATACALL_COMPLETE,
+                    DataServiceCallback.RESULT_SUCCESS,
+                    tunnelState.getDataServiceCallback(),
+                    respBuilder.build());
+            return;
+        }
+
+        // iwlan service triggered teardown
+        if (tunnelState.getState() == IwlanDataServiceProvider.TunnelState.TUNNEL_IN_BRINGDOWN) {
+
+            // IO exception happens when IKE library fails to retransmit requests.
+            // This can happen for multiple reasons:
+            // 1. Network disconnection due to wifi off.
+            // 2. Epdg server does not respond.
+            // 3. Socket send/receive fails.
+            // Ignore this during tunnel bring down.
+            if (iwlanError.getErrorType() != IwlanError.NO_ERROR
+                    && iwlanError.getErrorType() != IwlanError.IKE_INTERNAL_IO_EXCEPTION) {
+                Log.e(TAG, "Unexpected error during tunnel bring down: " + iwlanError);
+            }
+
+            iwlanDataServiceProvider.deliverCallback(
+                    IwlanDataServiceProvider.CALLBACK_TYPE_DEACTIVATE_DATACALL_COMPLETE,
+                    DataServiceCallback.RESULT_SUCCESS,
+                    tunnelState.getDataServiceCallback(),
+                    null);
+
+            return;
+        }
+
+        // just update list of data calls. No way to send error up
+        iwlanDataServiceProvider.notifyDataCallListChanged(iwlanDataServiceProvider.getCallList());
+
+        // Report IwlanPdnDisconnectedReason due to the disconnection is neither for
+        // SETUP_DATA_CALL nor DEACTIVATE_DATA_CALL request.
+        metricsAtom.setDataCallFailCause(
+                ErrorPolicyManager.getInstance(mContext, iwlanDataServiceProvider.getSlotIndex())
+                        .getDataFailCause(apnName));
+
+        WifiManager wifiManager = mContext.getSystemService(WifiManager.class);
+        if (wifiManager == null) {
+            Log.e(TAG, "Could not find wifiManager");
+            return;
+        }
+
+        WifiInfo wifiInfo = getWifiInfo(sNetworkCapabilities);
+        if (wifiInfo == null) {
+            Log.e(TAG, "wifiInfo is null");
+            return;
+        }
+
+        metricsAtom.setWifiSignalValue(wifiInfo.getRssi());
+        metricsAtom.setMessageId(IwlanStatsLog.IWLAN_PDN_DISCONNECTED_REASON_REPORTED);
+    }
+
+    private void handleSetupDataCall(
+            int accessNetworkType,
+            @NonNull DataProfile dataProfile,
+            boolean isRoaming,
+            int reason,
+            @Nullable LinkProperties linkProperties,
+            @IntRange(from = 0, to = 15) int pduSessionId,
+            @NonNull DataServiceCallback callback,
+            IwlanDataServiceProvider iwlanDataServiceProvider) {
+
+        if ((accessNetworkType != AccessNetworkType.IWLAN)
+                || (dataProfile == null)
+                || (dataProfile.getApnSetting() == null)
+                || (linkProperties == null && reason == DataService.REQUEST_REASON_HANDOVER)) {
+
+            iwlanDataServiceProvider.deliverCallback(
+                    IwlanDataServiceProvider.CALLBACK_TYPE_SETUP_DATACALL_COMPLETE,
+                    DataServiceCallback.RESULT_ERROR_INVALID_ARG,
+                    callback,
+                    null);
+            return;
+        }
+
+        int slotId = iwlanDataServiceProvider.getSlotIndex();
+        boolean isCSTEnabled = IwlanHelper.isCrossSimCallingEnabled(mContext, slotId);
+        boolean networkConnected = isNetworkConnected(isActiveDataOnOtherSub(slotId), isCSTEnabled);
+        Log.d(
+                TAG + "[" + slotId + "]",
+                "isDds: "
+                        + IwlanHelper.isDefaultDataSlot(mContext, slotId)
+                        + ", isActiveDataOnOtherSub: "
+                        + isActiveDataOnOtherSub(slotId)
+                        + ", isCstEnabled: "
+                        + isCSTEnabled
+                        + ", transport: "
+                        + sDefaultDataTransport);
+
+        if (!networkConnected) {
+            iwlanDataServiceProvider.deliverCallback(
+                    IwlanDataServiceProvider.CALLBACK_TYPE_SETUP_DATACALL_COMPLETE,
+                    5 /* DataServiceCallback.RESULT_ERROR_TEMPORARILY_UNAVAILABLE
+                       */,
+                    callback,
+                    null);
+            return;
+        }
+
+        // Update Network & LinkProperties to EpdgTunnelManager
+        iwlanDataServiceProvider.mEpdgTunnelManager.updateNetwork(sNetwork, sLinkProperties);
+        Log.d(TAG, "Update Network for SetupDataCall request");
+
+        IwlanDataServiceProvider.TunnelState tunnelState =
+                iwlanDataServiceProvider.mTunnelStateForApn.get(
+                        dataProfile.getApnSetting().getApnName());
+
+        // Return the existing PDN if the pduSessionId is the same and the tunnel
+        // state is TUNNEL_UP.
+        if (tunnelState != null) {
+            if (tunnelState.getPduSessionId() == pduSessionId
+                    && tunnelState.getState() == IwlanDataServiceProvider.TunnelState.TUNNEL_UP) {
+                Log.w(
+                        TAG + "[" + slotId + "]",
+                        "The tunnel for "
+                                + dataProfile.getApnSetting().getApnName()
+                                + " already exists.");
+                iwlanDataServiceProvider.deliverCallback(
+                        IwlanDataServiceProvider.CALLBACK_TYPE_SETUP_DATACALL_COMPLETE,
+                        DataServiceCallback.RESULT_SUCCESS,
+                        callback,
+                        iwlanDataServiceProvider.apnTunnelStateToDataCallResponse(
+                                dataProfile.getApnSetting().getApnName()));
+            } else {
+                Log.e(
+                        TAG + "[" + slotId + "]",
+                        "Force close the existing PDN. pduSessionId = "
+                                + tunnelState.getPduSessionId()
+                                + " Tunnel State = "
+                                + tunnelState.getState());
+                iwlanDataServiceProvider.mEpdgTunnelManager.closeTunnel(
+                        dataProfile.getApnSetting().getApnName(),
+                        true /* forceClose */,
+                        iwlanDataServiceProvider.getIwlanTunnelCallback(),
+                        BRINGDOWN_REASON_SERVICE_OUT_OF_SYNC);
+                iwlanDataServiceProvider.deliverCallback(
+                        IwlanDataServiceProvider.CALLBACK_TYPE_SETUP_DATACALL_COMPLETE,
+                        5 /* DataServiceCallback
+                          .RESULT_ERROR_TEMPORARILY_UNAVAILABLE */,
+                        callback,
+                        null);
+            }
+            return;
+        }
+
+        int apnTypeBitmask = dataProfile.getApnSetting().getApnTypeBitmask();
+        boolean isIms = hasApnTypes(apnTypeBitmask, ApnSetting.TYPE_IMS);
+        boolean isEmergency = hasApnTypes(apnTypeBitmask, ApnSetting.TYPE_EMERGENCY);
+
+        boolean isDataCallSetupWithN1 = iwlanDataServiceProvider.needIncludeN1ModeCapability();
+
+        // Override N1_MODE_CAPABILITY exclusion only for Emergency PDN due to carrier
+        // network limitations
+        if (IwlanCarrierConfig.getConfigBoolean(
+                        mContext,
+                        slotId,
+                        IwlanCarrierConfig.KEY_N1_MODE_EXCLUSION_FOR_EMERGENCY_SESSION_BOOL)
+                && isEmergency) {
+            isDataCallSetupWithN1 = false;
+        }
+
+        TunnelSetupRequest.Builder tunnelReqBuilder =
+                TunnelSetupRequest.builder()
+                        .setApnName(dataProfile.getApnSetting().getApnName())
+                        .setIsRoaming(isRoaming)
+                        .setPduSessionId(
+                                isDataCallSetupWithN1 ? pduSessionId : PDU_SESSION_ID_UNSET)
+                        .setApnIpProtocol(
+                                isRoaming
+                                        ? dataProfile.getApnSetting().getRoamingProtocol()
+                                        : dataProfile.getApnSetting().getProtocol())
+                        .setRequestPcscf(isIms || isEmergency)
+                        .setIsEmergency(isEmergency);
+
+        if (reason == DataService.REQUEST_REASON_HANDOVER) {
+            // for now assume that, at max,  only one address of each type (v4/v6).
+            // TODO: Check if multiple ips can be sent in ike tunnel setup
+            for (LinkAddress lAddr : linkProperties.getLinkAddresses()) {
+                if (lAddr.isIpv4()) {
+                    tunnelReqBuilder.setSrcIpv4Address(lAddr.getAddress());
+                } else if (lAddr.isIpv6()) {
+                    tunnelReqBuilder.setSrcIpv6Address(lAddr.getAddress());
+                    tunnelReqBuilder.setSrcIpv6AddressPrefixLength(lAddr.getPrefixLength());
+                }
+            }
+        }
+
+        iwlanDataServiceProvider.setTunnelState(
+                dataProfile,
+                callback,
+                IwlanDataServiceProvider.TunnelState.TUNNEL_IN_BRINGUP,
+                null,
+                (reason == DataService.REQUEST_REASON_HANDOVER),
+                pduSessionId,
+                isIms || isEmergency,
+                isDataCallSetupWithN1);
+
+        boolean result =
+                iwlanDataServiceProvider.mEpdgTunnelManager.bringUpTunnel(
+                        tunnelReqBuilder.build(),
+                        iwlanDataServiceProvider.getIwlanTunnelCallback());
+        Log.d(TAG + "[" + slotId + "]", "bringup Tunnel with result:" + result);
+        if (!result) {
+            iwlanDataServiceProvider.deliverCallback(
+                    IwlanDataServiceProvider.CALLBACK_TYPE_SETUP_DATACALL_COMPLETE,
+                    DataServiceCallback.RESULT_ERROR_INVALID_ARG,
+                    callback,
+                    null);
         }
     }
 
+    private void handleDeactivateDataCall(DeactivateDataCallData data) {
+        handleDeactivateDataCall(data, false);
+    }
+
+    private void handleDeactivateDataCallWithDelay(DeactivateDataCallData data) {
+        handleDeactivateDataCall(data, true);
+    }
+
+    private void handleDeactivateDataCall(DeactivateDataCallData data, boolean isWithDelay) {
+        IwlanDataServiceProvider serviceProvider = data.mIwlanDataServiceProvider;
+        String matchingApn = findMatchingApn(serviceProvider, data.mCid);
+
+        if (matchingApn == null) {
+            deliverDeactivationError(serviceProvider, data.mCallback);
+            return;
+        }
+
+        if (isWithDelay) {
+            Log.d(TAG, "Delaying deactivation for APN: " + matchingApn);
+            scheduleDelayedDeactivateDataCall(serviceProvider, data, matchingApn);
+            return;
+        }
+        Log.d(TAG, "Processing deactivation for APN: " + matchingApn);
+        processDeactivateDataCall(serviceProvider, data, matchingApn);
+    }
+
+    private static String findMatchingApn(IwlanDataServiceProvider serviceProvider, int cid) {
+        return serviceProvider.mTunnelStateForApn.keySet().stream()
+                .filter(apn -> apn.hashCode() == cid)
+                .findFirst()
+                .orElse(null);
+    }
+
+    private static void deliverDeactivationError(
+            IwlanDataServiceProvider serviceProvider, DataServiceCallback callback) {
+        serviceProvider.deliverCallback(
+                IwlanDataServiceProvider.CALLBACK_TYPE_DEACTIVATE_DATACALL_COMPLETE,
+                DataServiceCallback.RESULT_ERROR_INVALID_ARG,
+                callback,
+                null);
+    }
+
+    private void scheduleDelayedDeactivateDataCall(
+            IwlanDataServiceProvider serviceProvider,
+            DeactivateDataCallData data,
+            String matchingApn) {
+        IwlanDataServiceProvider.TunnelState tunnelState =
+                serviceProvider.mTunnelStateForApn.get(matchingApn);
+        tunnelState.setPendingDeactivateDataCallData(data);
+        tunnelState.setState(IwlanDataServiceProvider.TunnelState.TUNNEL_IN_BRINGDOWN);
+        Handler handler = getHandler();
+        handler.sendMessageDelayed(
+                handler.obtainMessage(EVENT_DEACTIVATE_DATA_CALL, data),
+                data.mDelayTimeSeconds * 1000L);
+    }
+
+    private static void processDeactivateDataCall(
+            IwlanDataServiceProvider serviceProvider,
+            DeactivateDataCallData data,
+            String matchingApn) {
+        int slotId = serviceProvider.getSlotIndex();
+        boolean isNetworkLost =
+                !isNetworkConnected(
+                        isActiveDataOnOtherSub(slotId),
+                        IwlanHelper.isCrossSimCallingEnabled(mContext, slotId));
+        boolean isHandoverSuccessful = (data.mReason == REQUEST_REASON_HANDOVER);
+
+        IwlanDataServiceProvider.TunnelState tunnelState =
+                serviceProvider.mTunnelStateForApn.get(matchingApn);
+        tunnelState.setState(IwlanDataServiceProvider.TunnelState.TUNNEL_IN_BRINGDOWN);
+        tunnelState.setDataServiceCallback(data.mCallback);
+
+        serviceProvider.mEpdgTunnelManager.closeTunnel(
+                matchingApn,
+                isNetworkLost || isHandoverSuccessful, /* forceClose */
+                serviceProvider.getIwlanTunnelCallback(),
+                BRINGDOWN_REASON_DEACTIVATE_DATA_CALL);
+    }
+
+    private static void handleNetworkValidationRequest(
+            NetworkValidationInfo networkValidationInfo) {
+        IwlanDataServiceProvider iwlanDataServiceProvider =
+                networkValidationInfo.mIwlanDataServiceProvider;
+        int cid = networkValidationInfo.mCid;
+        Executor executor = networkValidationInfo.mExecutor;
+        Consumer<Integer> resultCodeCallback = networkValidationInfo.mResultCodeCallback;
+        IwlanDataServiceProvider.TunnelState tunnelState;
+
+        String apnName = findMatchingApn(iwlanDataServiceProvider, cid);
+        int resultCode;
+        if (apnName == null) {
+            Log.w(TAG, "no matching APN name found for network validation.");
+            resultCode = DataServiceCallback.RESULT_ERROR_UNSUPPORTED;
+        } else {
+            iwlanDataServiceProvider.mEpdgTunnelManager.requestNetworkValidationForApn(apnName);
+            resultCode = DataServiceCallback.RESULT_SUCCESS;
+            tunnelState = iwlanDataServiceProvider.mTunnelStateForApn.get(apnName);
+            if (tunnelState == null) {
+                Log.w(TAG, "EVENT_REQUEST_NETWORK_VALIDATION: tunnel state is null.");
+            } else {
+                tunnelState.setNetworkValidationStatus(
+                        PreciseDataConnectionState.NETWORK_VALIDATION_IN_PROGRESS);
+            }
+        }
+        executor.execute(() -> resultCodeCallback.accept(resultCode));
+    }
+
+    private static void handleLivenessStatusChange(
+            TunnelValidationStatusData validationStatusData) {
+        IwlanDataServiceProvider iwlanDataServiceProvider =
+                validationStatusData.mIwlanDataServiceProvider;
+        String apnName = validationStatusData.mApnName;
+        IwlanDataServiceProvider.TunnelState tunnelState =
+                iwlanDataServiceProvider.mTunnelStateForApn.get(apnName);
+        if (tunnelState == null) {
+            Log.w(TAG, "EVENT_ON_LIVENESS_STATUS_CHANGED: tunnel state is null.");
+            return;
+        }
+        tunnelState.setNetworkValidationStatus(validationStatusData.mStatus);
+        iwlanDataServiceProvider.notifyDataCallListChanged(iwlanDataServiceProvider.getCallList());
+    }
+
+    private String requestReasonToString(int reason) {
+        return switch (reason) {
+            case DataService.REQUEST_REASON_UNKNOWN -> "UNKNOWN";
+            case DataService.REQUEST_REASON_NORMAL -> "NORMAL";
+            case DataService.REQUEST_REASON_SHUTDOWN -> "SHUTDOWN";
+            case DataService.REQUEST_REASON_HANDOVER -> "HANDOVER";
+            default -> "UNKNOWN(" + reason + ")";
+        };
+    }
+
     @Override
     public void dump(FileDescriptor fd, PrintWriter pw, String[] args) {
         String transport = "UNSPECIFIED";
diff --git a/src/com/google/android/iwlan/IwlanError.java b/src/com/google/android/iwlan/IwlanError.java
index 26b9e7d..c16233e 100644
--- a/src/com/google/android/iwlan/IwlanError.java
+++ b/src/com/google/android/iwlan/IwlanError.java
@@ -111,14 +111,14 @@ public class IwlanError {
      */
     public IwlanError(@NonNull Exception exception) {
         // resolve into specific types if possible
-        if (exception instanceof IkeProtocolException) {
-            IwlanErrorIkeProtocolException((IkeProtocolException) exception);
-        } else if (exception instanceof IkeIOException) {
-            IwlanErrorIkeIOException((IkeIOException) exception);
-        } else if (exception instanceof IkeInternalException) {
-            IwlanErrorIkeInternalException((IkeInternalException) exception);
-        } else if (exception instanceof IkeNetworkLostException) {
-            IwlanErrorIkeNetworkLostException((IkeNetworkLostException) exception);
+        if (exception instanceof IkeProtocolException ikeProtocolException) {
+            IwlanErrorIkeProtocolException(ikeProtocolException);
+        } else if (exception instanceof IkeIOException ikeIOException) {
+            IwlanErrorIkeIOException(ikeIOException);
+        } else if (exception instanceof IkeInternalException ikeInternalException) {
+            IwlanErrorIkeInternalException(ikeInternalException);
+        } else if (exception instanceof IkeNetworkLostException ikeNetworkLostException) {
+            IwlanErrorIkeNetworkLostException(ikeNetworkLostException);
         } else {
             mErrorType = IKE_GENERIC_EXCEPTION;
             mException = exception;
@@ -222,4 +222,23 @@ public class IwlanError {
         }
         return ret;
     }
+
+    @Override
+    public int hashCode() {
+        int result = Integer.hashCode(mErrorType); // Use Integer.hashCode for int primitive
+
+        if (mException != null) {
+            result = 31 * result + mException.getClass().hashCode();
+
+            if (mException instanceof IkeProtocolException) {
+                int ikeErrorType = ((IkeProtocolException) mException).getErrorType();
+                result =
+                        31 * result
+                                + Integer.hashCode(
+                                        ikeErrorType); // Use Integer.hashCode for int primitive
+            }
+        }
+
+        return result;
+    }
 }
diff --git a/src/com/google/android/iwlan/IwlanEventListener.java b/src/com/google/android/iwlan/IwlanEventListener.java
index 0a6e997..20433a3 100644
--- a/src/com/google/android/iwlan/IwlanEventListener.java
+++ b/src/com/google/android/iwlan/IwlanEventListener.java
@@ -51,7 +51,6 @@ import java.util.concurrent.ConcurrentHashMap;
 
 public class IwlanEventListener {
 
-    private final FeatureFlags mFeatureFlags;
     public static final int UNKNOWN_EVENT = -1;
 
     /** On {@link IwlanCarrierConfigChangeListener#onCarrierConfigChanged} is called. */
@@ -62,6 +61,7 @@ public class IwlanEventListener {
 
     /** Airplane mode turned off or disabled. */
     public static final int APM_DISABLE_EVENT = 3;
+
     /** Airplane mode turned on or enabled */
     public static final int APM_ENABLE_EVENT = 4;
 
@@ -95,6 +95,8 @@ public class IwlanEventListener {
     /** On Preferred Network Type changed */
     public static final int PREFERRED_NETWORK_TYPE_CHANGED_EVENT = 13;
 
+    public static final int SCREEN_ON_EVENT = 14;
+
     /* Events used and handled by IwlanDataService internally */
     public static final int DATA_SERVICE_INTERNAL_EVENT_BASE = 100;
 
@@ -115,6 +117,7 @@ public class IwlanEventListener {
         CELLINFO_CHANGED_EVENT,
         CALL_STATE_CHANGED_EVENT,
         PREFERRED_NETWORK_TYPE_CHANGED_EVENT,
+        SCREEN_ON_EVENT,
     })
     @interface IwlanEventType {}
 
@@ -198,9 +201,7 @@ public class IwlanEventListener {
         }
     }
 
-    /**
-     * Returns IwlanEventListener instance
-     */
+    /** Returns IwlanEventListener instance */
     public static IwlanEventListener getInstance(@NonNull Context context, int slotId) {
         return mInstances.computeIfAbsent(
                 slotId, k -> new IwlanEventListener(context, slotId, new FeatureFlagsImpl()));
@@ -303,6 +304,9 @@ public class IwlanEventListener {
                     }
                 }
                 break;
+            case Intent.ACTION_SCREEN_ON:
+                mInstances.values().forEach(instance -> instance.updateHandlers(SCREEN_ON_EVENT));
+                break;
         }
     }
 
@@ -355,46 +359,21 @@ public class IwlanEventListener {
      * @param event String form of the event.
      */
     public static int getUnthrottlingEvent(String event) {
-        int ret = UNKNOWN_EVENT;
-        switch (event) {
-            case "CARRIER_CONFIG_CHANGED_EVENT":
-                ret = CARRIER_CONFIG_CHANGED_EVENT;
-                break;
-            case "WIFI_DISABLE_EVENT":
-                ret = WIFI_DISABLE_EVENT;
-                break;
-            case "APM_DISABLE_EVENT":
-                ret = APM_DISABLE_EVENT;
-                break;
-            case "APM_ENABLE_EVENT":
-                ret = APM_ENABLE_EVENT;
-                break;
-            case "WIFI_AP_CHANGED_EVENT":
-                ret = WIFI_AP_CHANGED_EVENT;
-                break;
-            case "WIFI_CALLING_ENABLE_EVENT":
-                ret = WIFI_CALLING_ENABLE_EVENT;
-                break;
-            case "WIFI_CALLING_DISABLE_EVENT":
-                ret = WIFI_CALLING_DISABLE_EVENT;
-                break;
-            case "CROSS_SIM_CALLING_ENABLE_EVENT":
-                ret = CROSS_SIM_CALLING_ENABLE_EVENT;
-                break;
-            case "CROSS_SIM_CALLING_DISABLE_EVENT":
-                ret = CROSS_SIM_CALLING_DISABLE_EVENT;
-                break;
-            case "CARRIER_CONFIG_UNKNOWN_CARRIER_EVENT":
-                ret = CARRIER_CONFIG_UNKNOWN_CARRIER_EVENT;
-                break;
-            case "CELLINFO_CHANGED_EVENT":
-                ret = CELLINFO_CHANGED_EVENT;
-                break;
-            case "PREFERRED_NETWORK_TYPE_CHANGED_EVENT":
-                ret = PREFERRED_NETWORK_TYPE_CHANGED_EVENT;
-                break;
-        }
-        return ret;
+        return switch (event) {
+            case "CARRIER_CONFIG_CHANGED_EVENT" -> CARRIER_CONFIG_CHANGED_EVENT;
+            case "WIFI_DISABLE_EVENT" -> WIFI_DISABLE_EVENT;
+            case "APM_DISABLE_EVENT" -> APM_DISABLE_EVENT;
+            case "APM_ENABLE_EVENT" -> APM_ENABLE_EVENT;
+            case "WIFI_AP_CHANGED_EVENT" -> WIFI_AP_CHANGED_EVENT;
+            case "WIFI_CALLING_ENABLE_EVENT" -> WIFI_CALLING_ENABLE_EVENT;
+            case "WIFI_CALLING_DISABLE_EVENT" -> WIFI_CALLING_DISABLE_EVENT;
+            case "CROSS_SIM_CALLING_ENABLE_EVENT" -> CROSS_SIM_CALLING_ENABLE_EVENT;
+            case "CROSS_SIM_CALLING_DISABLE_EVENT" -> CROSS_SIM_CALLING_DISABLE_EVENT;
+            case "CARRIER_CONFIG_UNKNOWN_CARRIER_EVENT" -> CARRIER_CONFIG_UNKNOWN_CARRIER_EVENT;
+            case "CELLINFO_CHANGED_EVENT" -> CELLINFO_CHANGED_EVENT;
+            case "PREFERRED_NETWORK_TYPE_CHANGED_EVENT" -> PREFERRED_NETWORK_TYPE_CHANGED_EVENT;
+            default -> UNKNOWN_EVENT;
+        };
     }
 
     IwlanEventListener(Context context, int slotId, FeatureFlags featureFlags) {
@@ -402,8 +381,6 @@ public class IwlanEventListener {
         mSlotId = slotId;
         mSubId = SubscriptionManager.INVALID_SUBSCRIPTION_ID;
         SUB_TAG = IwlanEventListener.class.getSimpleName() + "[" + slotId + "]";
-        sIsAirplaneModeOn = null;
-        mFeatureFlags = featureFlags;
     }
 
     private void onCarrierConfigChanged(int subId, int carrierId) {
@@ -574,15 +551,11 @@ public class IwlanEventListener {
     }
 
     private String callStateToString(int state) {
-        switch (state) {
-            case TelephonyManager.CALL_STATE_IDLE:
-                return "CALL_STATE_IDLE";
-            case TelephonyManager.CALL_STATE_RINGING:
-                return "CALL_STATE_RINGING";
-            case TelephonyManager.CALL_STATE_OFFHOOK:
-                return "CALL_STATE_OFFHOOK";
-            default:
-                return "Unknown Call State (" + state + ")";
-        }
+        return switch (state) {
+            case TelephonyManager.CALL_STATE_IDLE -> "CALL_STATE_IDLE";
+            case TelephonyManager.CALL_STATE_RINGING -> "CALL_STATE_RINGING";
+            case TelephonyManager.CALL_STATE_OFFHOOK -> "CALL_STATE_OFFHOOK";
+            default -> "Unknown Call State (" + state + ")";
+        };
     }
 }
diff --git a/src/com/google/android/iwlan/IwlanHelper.java b/src/com/google/android/iwlan/IwlanHelper.java
index 917d694..85fc8cc 100644
--- a/src/com/google/android/iwlan/IwlanHelper.java
+++ b/src/com/google/android/iwlan/IwlanHelper.java
@@ -278,7 +278,7 @@ public class IwlanHelper {
         }
     }
 
-    static long elapsedRealtime() {
+    public static long elapsedRealtime() {
         /*Returns milliseconds since boot, including time spent in sleep.*/
         return SystemClock.elapsedRealtime();
     }
diff --git a/src/com/google/android/iwlan/IwlanNetworkService.java b/src/com/google/android/iwlan/IwlanNetworkService.java
index 00f0907..ad7bd59 100644
--- a/src/com/google/android/iwlan/IwlanNetworkService.java
+++ b/src/com/google/android/iwlan/IwlanNetworkService.java
@@ -83,7 +83,7 @@ public class IwlanNetworkService extends NetworkService {
     private static Transport sDefaultDataTransport = Transport.UNSPECIFIED_NETWORK;
 
     // This callback runs in the same thread as IwlanNetworkServiceHandler
-    final class IwlanNetworkMonitorCallback extends ConnectivityManager.NetworkCallback {
+    static final class IwlanNetworkMonitorCallback extends ConnectivityManager.NetworkCallback {
         /** Called when the framework connects and has declared a new network ready for use. */
         @Override
         public void onAvailable(Network network) {
@@ -150,7 +150,7 @@ public class IwlanNetworkService extends NetworkService {
         }
     }
 
-    final class IwlanOnSubscriptionsChangedListener
+    static final class IwlanOnSubscriptionsChangedListener
             extends SubscriptionManager.OnSubscriptionsChangedListener {
         /**
          * Callback invoked when there is any change to any SubscriptionInfo. Typically, this method
@@ -191,12 +191,10 @@ public class IwlanNetworkService extends NetworkService {
         @Override
         public void requestNetworkRegistrationInfo(int domain, NetworkServiceCallback callback) {
             getIwlanNetworkServiceHandler()
-                    .sendMessage(
-                            getIwlanNetworkServiceHandler()
-                                    .obtainMessage(
-                                            EVENT_NETWORK_REGISTRATION_INFO_REQUEST,
-                                            new NetworkRegistrationInfoRequestData(
-                                                    domain, callback, this)));
+                    .obtainMessage(
+                            EVENT_NETWORK_REGISTRATION_INFO_REQUEST,
+                            new NetworkRegistrationInfoRequestData(domain, callback, this))
+                    .sendToTarget();
         }
 
         /**
@@ -364,9 +362,8 @@ public class IwlanNetworkService extends NetworkService {
 
         IwlanNetworkServiceProvider np = new IwlanNetworkServiceProvider(slotIndex, this);
         getIwlanNetworkServiceHandler()
-                .sendMessage(
-                        getIwlanNetworkServiceHandler()
-                                .obtainMessage(EVENT_CREATE_NETWORK_SERVICE_PROVIDER, np));
+                .obtainMessage(EVENT_CREATE_NETWORK_SERVICE_PROVIDER, np)
+                .sendToTarget();
         return np;
     }
 
@@ -379,10 +376,10 @@ public class IwlanNetworkService extends NetworkService {
         NetworkSpecifier specifier = networkCapabilities.getNetworkSpecifier();
         TransportInfo transportInfo = networkCapabilities.getTransportInfo();
 
-        if (specifier instanceof TelephonyNetworkSpecifier) {
-            connectedDataSub = ((TelephonyNetworkSpecifier) specifier).getSubscriptionId();
-        } else if (transportInfo instanceof VcnTransportInfo) {
-            connectedDataSub = ((VcnTransportInfo) transportInfo).getSubId();
+        if (specifier instanceof TelephonyNetworkSpecifier telephonyNetworkSpecifier) {
+            connectedDataSub = telephonyNetworkSpecifier.getSubscriptionId();
+        } else if (transportInfo instanceof VcnTransportInfo vcnTransportInfo) {
+            connectedDataSub = vcnTransportInfo.getSubId();
         }
         return connectedDataSub;
     }
@@ -432,9 +429,8 @@ public class IwlanNetworkService extends NetworkService {
 
     public void removeNetworkServiceProvider(IwlanNetworkServiceProvider np) {
         getIwlanNetworkServiceHandler()
-                .sendMessage(
-                        getIwlanNetworkServiceHandler()
-                                .obtainMessage(EVENT_REMOVE_NETWORK_SERVICE_PROVIDER, np));
+                .obtainMessage(EVENT_REMOVE_NETWORK_SERVICE_PROVIDER, np)
+                .sendToTarget();
     }
 
     void initCallback() {
@@ -500,20 +496,17 @@ public class IwlanNetworkService extends NetworkService {
     }
 
     private static String eventToString(int event) {
-        switch (event) {
-            case IwlanEventListener.CROSS_SIM_CALLING_ENABLE_EVENT:
-                return "CROSS_SIM_CALLING_ENABLE_EVENT";
-            case IwlanEventListener.CROSS_SIM_CALLING_DISABLE_EVENT:
-                return "CROSS_SIM_CALLING_DISABLE_EVENT";
-            case EVENT_NETWORK_REGISTRATION_INFO_REQUEST:
-                return "EVENT_NETWORK_REGISTRATION_INFO_REQUEST";
-            case EVENT_CREATE_NETWORK_SERVICE_PROVIDER:
-                return "EVENT_CREATE_NETWORK_SERVICE_PROVIDER";
-            case EVENT_REMOVE_NETWORK_SERVICE_PROVIDER:
-                return "EVENT_REMOVE_NETWORK_SERVICE_PROVIDER";
-            default:
-                return "Unknown(" + event + ")";
-        }
+        return switch (event) {
+            case IwlanEventListener.CROSS_SIM_CALLING_ENABLE_EVENT ->
+                    "CROSS_SIM_CALLING_ENABLE_EVENT";
+            case IwlanEventListener.CROSS_SIM_CALLING_DISABLE_EVENT ->
+                    "CROSS_SIM_CALLING_DISABLE_EVENT";
+            case EVENT_NETWORK_REGISTRATION_INFO_REQUEST ->
+                    "EVENT_NETWORK_REGISTRATION_INFO_REQUEST";
+            case EVENT_CREATE_NETWORK_SERVICE_PROVIDER -> "EVENT_CREATE_NETWORK_SERVICE_PROVIDER";
+            case EVENT_REMOVE_NETWORK_SERVICE_PROVIDER -> "EVENT_REMOVE_NETWORK_SERVICE_PROVIDER";
+            default -> "Unknown(" + event + ")";
+        };
     }
 
     @Override
diff --git a/src/com/google/android/iwlan/IwlanTunnelMetricsImpl.java b/src/com/google/android/iwlan/IwlanTunnelMetricsImpl.java
deleted file mode 100644
index f0a3e68..0000000
--- a/src/com/google/android/iwlan/IwlanTunnelMetricsImpl.java
+++ /dev/null
@@ -1,46 +0,0 @@
-/*
- * Copyright (C) 2022 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-package com.google.android.iwlan;
-
-import android.os.Handler;
-
-import com.google.android.iwlan.IwlanDataService.IwlanDataServiceProvider;
-
-public class IwlanTunnelMetricsImpl implements TunnelMetricsInterface {
-    IwlanDataServiceProvider mDataServiceProvider;
-    Handler mIwlanDataServiceHandler;
-
-    private static final int EVENT_BASE = IwlanEventListener.DATA_SERVICE_INTERNAL_EVENT_BASE;
-    private static final int EVENT_TUNNEL_OPENED_METRICS = EVENT_BASE + 8;
-    private static final int EVENT_TUNNEL_CLOSED_METRICS = EVENT_BASE + 9;
-
-    public IwlanTunnelMetricsImpl(IwlanDataServiceProvider dsp, Handler handler) {
-        mDataServiceProvider = dsp;
-        mIwlanDataServiceHandler = handler;
-    }
-
-    public void onOpened(OnOpenedMetrics metricsData) {
-        metricsData.setIwlanDataServiceProvider(mDataServiceProvider);
-        mIwlanDataServiceHandler.sendMessage(
-                mIwlanDataServiceHandler.obtainMessage(EVENT_TUNNEL_OPENED_METRICS, metricsData));
-    }
-
-    public void onClosed(OnClosedMetrics metricsData) {
-        metricsData.setIwlanDataServiceProvider(mDataServiceProvider);
-        mIwlanDataServiceHandler.sendMessage(
-                mIwlanDataServiceHandler.obtainMessage(EVENT_TUNNEL_CLOSED_METRICS, metricsData));
-    }
-}
diff --git a/src/com/google/android/iwlan/TunnelMetricsInterface.java b/src/com/google/android/iwlan/TunnelMetricsInterface.java
index bd4539b..ab9a298 100644
--- a/src/com/google/android/iwlan/TunnelMetricsInterface.java
+++ b/src/com/google/android/iwlan/TunnelMetricsInterface.java
@@ -18,23 +18,15 @@ package com.google.android.iwlan;
 import android.support.annotation.NonNull;
 import android.support.annotation.Nullable;
 
-import com.google.android.iwlan.IwlanDataService.IwlanDataServiceProvider;
-
 import java.net.InetAddress;
 import java.util.Objects;
 
 public interface TunnelMetricsInterface {
-    /** Called for logging the tunnel is opened. */
-    void onOpened(OnOpenedMetrics metricsData);
-    /** Called for logging the tunnel is closed or bring up failed. */
-    void onClosed(OnClosedMetrics metricsData);
-
     class TunnelMetricsData {
         private final String mApnName;
         private final String mEpdgServerAddress;
         private final int mEpdgServerSelectionDuration;
         private final int mIkeTunnelEstablishmentDuration;
-        private IwlanDataServiceProvider mIwlanDataServiceProvider;
         private final boolean mIsNetworkValidated;
 
         protected TunnelMetricsData(Builder builder) {
@@ -63,14 +55,6 @@ public interface TunnelMetricsInterface {
             return mIkeTunnelEstablishmentDuration;
         }
 
-        public IwlanDataServiceProvider getIwlanDataServiceProvider() {
-            return mIwlanDataServiceProvider;
-        }
-
-        public void setIwlanDataServiceProvider(IwlanDataServiceProvider dsp) {
-            mIwlanDataServiceProvider = dsp;
-        }
-
         public boolean isNetworkValidated() {
             return mIsNetworkValidated;
         }
diff --git a/src/com/google/android/iwlan/epdg/EpdgSaProposal.java b/src/com/google/android/iwlan/epdg/EpdgSaProposal.java
index 871cc5c..2039c0a 100644
--- a/src/com/google/android/iwlan/epdg/EpdgSaProposal.java
+++ b/src/com/google/android/iwlan/epdg/EpdgSaProposal.java
@@ -204,19 +204,16 @@ abstract class EpdgSaProposal {
         return -1;
     }
 
-    /**
-     * Compares the priority of the transforms.
-     */
+    /** Compares the priority of the transforms. */
     protected int compareTransformPriority(Set<Integer> transformGroup, int item1, int item2) {
         return getIndexOf(transformGroup, item1) - getIndexOf(transformGroup, item2);
     }
 
     /**
-     * Compares the priority of the encryption/AEAD transforms.
-     * First value in pair is encryption/AEAD algorithm and
-     * second value in pair is key length of that algorithm.
-     * If Algorithms are same then compare the priotity of the key lengths else compare
-     * the priority of the algorithms.
+     * Compares the priority of the encryption/AEAD transforms. First value in pair is
+     * encryption/AEAD algorithm and second value in pair is key length of that algorithm. If
+     * Algorithms are same then compare the priotity of the key lengths else compare the priority of
+     * the algorithms.
      */
     protected int compareEncryptionTransformPriority(
             Set<Integer> algos,
diff --git a/src/com/google/android/iwlan/epdg/EpdgSelector.java b/src/com/google/android/iwlan/epdg/EpdgSelector.java
index b0b5c15..a3e2aa0 100644
--- a/src/com/google/android/iwlan/epdg/EpdgSelector.java
+++ b/src/com/google/android/iwlan/epdg/EpdgSelector.java
@@ -16,19 +16,25 @@
 
 package com.google.android.iwlan.epdg;
 
+import android.content.BroadcastReceiver;
 import android.content.Context;
+import android.content.Intent;
+import android.content.IntentFilter;
+import android.net.ConnectivityManager;
 import android.net.DnsResolver;
 import android.net.DnsResolver.DnsException;
 import android.net.InetAddresses;
+import android.net.LinkAddress;
+import android.net.LinkProperties;
 import android.net.Network;
+import android.net.ipsec.ike.exceptions.IkeException;
+import android.net.ipsec.ike.exceptions.IkeIOException;
+import android.net.ipsec.ike.exceptions.IkeProtocolException;
 import android.support.annotation.IntDef;
 import android.support.annotation.NonNull;
 import android.support.annotation.Nullable;
 import android.telephony.CarrierConfigManager;
-import android.telephony.CellIdentityGsm;
-import android.telephony.CellIdentityLte;
 import android.telephony.CellIdentityNr;
-import android.telephony.CellIdentityWcdma;
 import android.telephony.CellInfo;
 import android.telephony.CellInfoGsm;
 import android.telephony.CellInfoLte;
@@ -39,6 +45,7 @@ import android.telephony.DataFailCause;
 import android.telephony.SubscriptionInfo;
 import android.telephony.SubscriptionManager;
 import android.telephony.TelephonyManager;
+import android.telephony.data.ApnSetting;
 import android.text.TextUtils;
 import android.util.Log;
 
@@ -88,10 +95,13 @@ public class EpdgSelector {
     private final int mSlotId;
     private static final ConcurrentHashMap<Integer, EpdgSelector> mSelectorInstances =
             new ConcurrentHashMap<>();
+
+    private final ConnectivityManager mConnectivityManager;
+
     private int mV4PcoId = -1;
     private int mV6PcoId = -1;
-    private List<byte[]> mV4PcoData;
-    private List<byte[]> mV6PcoData;
+    private final List<byte[]> mV4PcoData = new ArrayList<>();
+    private final List<byte[]> mV6PcoData = new ArrayList<>();
     @NonNull private final ErrorPolicyManager mErrorPolicyManager;
 
     // Temporary excluded IP addresses due to recent failures. Cleared after tunnel opened
@@ -162,18 +172,32 @@ public class EpdgSelector {
         mSlotId = slotId;
         mFeatureFlags = featureFlags;
 
-        mV4PcoData = new ArrayList<>();
-        mV6PcoData = new ArrayList<>();
-
-        mV4PcoData = new ArrayList<>();
-        mV6PcoData = new ArrayList<>();
+        mConnectivityManager = context.getSystemService(ConnectivityManager.class);
 
         mErrorPolicyManager = ErrorPolicyManager.getInstance(mContext, mSlotId);
-
+        registerBroadcastReceiver();
         mTemporaryExcludedAddresses = new HashSet<>();
         initializeExecutors();
     }
 
+    private void registerBroadcastReceiver() {
+        BroadcastReceiver mBroadcastReceiver =
+                new BroadcastReceiver() {
+                    @Override
+                    public void onReceive(Context context, Intent intent) {
+                        String action = intent.getAction();
+                        Log.d(TAG, "onReceive: " + action);
+                        if (Objects.equals(
+                                action, TelephonyManager.ACTION_CARRIER_SIGNAL_PCO_VALUE)) {
+                            processCarrierSignalPcoValue(intent);
+                        }
+                    }
+                };
+        IntentFilter intentFilter =
+                new IntentFilter(TelephonyManager.ACTION_CARRIER_SIGNAL_PCO_VALUE);
+        mContext.registerReceiver(mBroadcastReceiver, intentFilter, Context.RECEIVER_EXPORTED);
+    }
+
     private void initializeExecutors() {
         int maxEpdgSelectionThreads = mFeatureFlags.preventEpdgSelectionThreadsExhausted() ? 3 : 2;
 
@@ -210,42 +234,7 @@ public class EpdgSelector {
         return mSelectorInstances.get(slotId);
     }
 
-    public boolean setPcoData(int pcoId, @NonNull byte[] pcoData) {
-        Log.d(
-                TAG,
-                "onReceive PcoId:"
-                        + String.format("0x%04x", pcoId)
-                        + " PcoData:"
-                        + Arrays.toString(pcoData));
-
-        int PCO_ID_IPV6 =
-                IwlanCarrierConfig.getConfigInt(
-                        mContext, mSlotId, CarrierConfigManager.Iwlan.KEY_EPDG_PCO_ID_IPV6_INT);
-        int PCO_ID_IPV4 =
-                IwlanCarrierConfig.getConfigInt(
-                        mContext, mSlotId, CarrierConfigManager.Iwlan.KEY_EPDG_PCO_ID_IPV4_INT);
-
-        Log.d(
-                TAG,
-                "PCO_ID_IPV6:"
-                        + String.format("0x%04x", PCO_ID_IPV6)
-                        + " PCO_ID_IPV4:"
-                        + String.format("0x%04x", PCO_ID_IPV4));
-
-        if (pcoId == PCO_ID_IPV4) {
-            mV4PcoId = pcoId;
-            mV4PcoData.add(pcoData);
-            return true;
-        } else if (pcoId == PCO_ID_IPV6) {
-            mV6PcoId = pcoId;
-            mV6PcoData.add(pcoData);
-            return true;
-        }
-
-        return false;
-    }
-
-    public void clearPcoData() {
+    private void clearPcoData() {
         Log.d(TAG, "Clear PCO data");
         mV4PcoId = -1;
         mV6PcoId = -1;
@@ -262,14 +251,17 @@ public class EpdgSelector {
     }
 
     /**
-     * Notify {@link EpdgSelector} that failed to connect to an ePDG. EpdgSelector will add the
-     * {@code ipAddress} into excluded list and will not retry until any ePDG connected successfully
-     * or all ip addresses candidates are tried.
+     * Notify {@link EpdgSelector} that failed to connect to an ePDG due to IKE exception.
+     * EpdgSelector will add the {@code ipAddress} into excluded list and will not retry until any
+     * ePDG connected successfully or all ip addresses candidates are tried.
      *
      * @param ipAddress the ePDG ip address that failed to connect
+     * @param cause the failure cause {@link IkeException} of the connection
      */
-    void onEpdgConnectionFailed(InetAddress ipAddress) {
-        excludeIpAddress(ipAddress);
+    void onEpdgConnectionFailed(InetAddress ipAddress, IkeException cause) {
+        if (cause instanceof IkeProtocolException || cause instanceof IkeIOException) {
+            excludeIpAddress(ipAddress);
+        }
     }
 
     private void excludeIpAddress(InetAddress ipAddress) {
@@ -294,10 +286,10 @@ public class EpdgSelector {
 
     private CompletableFuture<Map.Entry<String, List<InetAddress>>> submitDnsResolverQuery(
             String domainName, Network network, int queryType, Executor executor) {
-        CompletableFuture<Map.Entry<String, List<InetAddress>>> result = new CompletableFuture();
+        CompletableFuture<Map.Entry<String, List<InetAddress>>> result = new CompletableFuture<>();
 
         final DnsResolver.Callback<List<InetAddress>> cb =
-                new DnsResolver.Callback<List<InetAddress>>() {
+                new DnsResolver.Callback<>() {
                     @Override
                     public void onAnswer(@NonNull final List<InetAddress> answer, final int rcode) {
                         if (rcode != 0) {
@@ -357,8 +349,7 @@ public class EpdgSelector {
     // even if any future throw an exception.
     private <T> CompletableFuture<List<T>> allOf(List<CompletableFuture<T>> futuresList) {
         CompletableFuture<Void> allFuturesResult =
-                CompletableFuture.allOf(
-                        futuresList.toArray(new CompletableFuture[futuresList.size()]));
+                CompletableFuture.allOf(futuresList.toArray(new CompletableFuture[0]));
         return allFuturesResult.thenApply(
                 v ->
                         futuresList.stream()
@@ -367,14 +358,17 @@ public class EpdgSelector {
                                 .collect(Collectors.<T>toList()));
     }
 
-    @VisibleForTesting
-    protected boolean hasIpv4Address(Network network) {
-        return IwlanHelper.hasIpv4Address(IwlanHelper.getAllAddressesForNetwork(mContext, network));
+    private boolean hasLocalIpv4Address(Network network) {
+        LinkProperties linkProperties = mConnectivityManager.getLinkProperties(network);
+        return linkProperties != null
+                && linkProperties.getAllLinkAddresses().stream().anyMatch(LinkAddress::isIpv4);
     }
 
-    @VisibleForTesting
-    protected boolean hasIpv6Address(Network network) {
-        return IwlanHelper.hasIpv6Address(IwlanHelper.getAllAddressesForNetwork(mContext, network));
+    private boolean hasLocalIpv6Address(Network network) {
+        LinkProperties linkProperties = mConnectivityManager.getLinkProperties(network);
+        // TODO(b/362349553): Restrict usage to global IPv6 addresses until the IKE limitation is
+        // removed.
+        return linkProperties != null && linkProperties.hasGlobalIpv6Address();
     }
 
     private void printParallelDnsResult(Map<String, List<InetAddress>> domainNameToIpAddresses) {
@@ -421,13 +415,15 @@ public class EpdgSelector {
      * @param filter Selects for IPv4, IPv6 (or both) addresses from the resulting DNS records
      * @param network {@link Network} Network on which to run the DNS query.
      * @param timeout timeout in seconds.
-     * @return List of unique IP addresses corresponding to the domainNames.
+     * @return Map of unique IP addresses corresponding to the domainNames.
      */
-    private LinkedHashMap<String, List<InetAddress>> getIP(
+    private Map<String, List<InetAddress>> getIP(
             List<String> domainNames, int filter, Network network, long timeout) {
         // LinkedHashMap preserves insertion order (and hence priority) of domain names passed in.
         LinkedHashMap<String, List<InetAddress>> domainNameToIpAddr = new LinkedHashMap<>();
 
+        if (!hasLocalIpv6Address(network)) filter = PROTO_FILTER_IPV4;
+
         List<CompletableFuture<Map.Entry<String, List<InetAddress>>>> futuresList =
                 new ArrayList<>();
         for (String domainName : domainNames) {
@@ -440,12 +436,12 @@ public class EpdgSelector {
 
             domainNameToIpAddr.put(domainName, new ArrayList<>());
             // Dispatches separate IPv4 and IPv6 queries to avoid being blocked on either result.
-            if (hasIpv4Address(network)) {
+            if (hasLocalIpv4Address(network)) {
                 futuresList.add(
                         submitDnsResolverQuery(
                                 domainName, network, DnsResolver.TYPE_A, mDnsResolutionExecutor));
             }
-            if (hasIpv6Address(network)) {
+            if (hasLocalIpv6Address(network)) {
                 futuresList.add(
                         submitDnsResolverQuery(
                                 domainName,
@@ -500,7 +496,7 @@ public class EpdgSelector {
      */
     private void getIP(
             String domainName, int filter, List<InetAddress> validIpList, Network network) {
-        List<InetAddress> ipList = new ArrayList<InetAddress>();
+        List<InetAddress> ipList = new ArrayList<>();
 
         // Get All IP for each domain name
         Log.d(TAG, "Input domainName : " + domainName);
@@ -510,9 +506,9 @@ public class EpdgSelector {
             ipList.add(InetAddresses.parseNumericAddress(domainName));
         } else {
             try {
-                CompletableFuture<List<InetAddress>> result = new CompletableFuture();
+                CompletableFuture<List<InetAddress>> result = new CompletableFuture<>();
                 final DnsResolver.Callback<List<InetAddress>> cb =
-                        new DnsResolver.Callback<List<InetAddress>>() {
+                        new DnsResolver.Callback<>() {
                             @Override
                             public void onAnswer(
                                     @NonNull final List<InetAddress> answer, final int rcode) {
@@ -565,14 +561,14 @@ public class EpdgSelector {
                 mContext.getSystemService(SubscriptionManager.class);
         if (subscriptionManager == null) {
             Log.e(TAG, "SubscriptionManager is NULL");
-            return plmnsFromCarrierConfig.toArray(new String[plmnsFromCarrierConfig.size()]);
+            return plmnsFromCarrierConfig.toArray(new String[0]);
         }
 
         SubscriptionInfo subInfo =
                 subscriptionManager.getActiveSubscriptionInfoForSimSlotIndex(mSlotId);
         if (subInfo == null) {
             Log.e(TAG, "SubscriptionInfo is NULL");
-            return plmnsFromCarrierConfig.toArray(new String[plmnsFromCarrierConfig.size()]);
+            return plmnsFromCarrierConfig.toArray(new String[0]);
         }
 
         // Get MCCMNC from IMSI
@@ -603,7 +599,7 @@ public class EpdgSelector {
                     break;
                 case CarrierConfigManager.Iwlan.EPDG_PLMN_EHPLMN_FIRST:
                     if (!ehplmns.isEmpty()) {
-                        combinedList.add(ehplmns.get(0));
+                        combinedList.add(ehplmns.getFirst());
                     }
                     break;
                 default:
@@ -620,7 +616,7 @@ public class EpdgSelector {
                         .toList();
 
         Log.d(TAG, "Final plmn list:" + combinedList);
-        return combinedList.toArray(new String[combinedList.size()]);
+        return combinedList.toArray(new String[0]);
     }
 
     private List<String> getPlmnsFromCarrierConfig() {
@@ -637,8 +633,8 @@ public class EpdgSelector {
         return plmnsFromCarrierConfig.contains(new StringBuilder(plmn).insert(3, "-").toString());
     }
 
-    private ArrayList<InetAddress> removeDuplicateIp(List<InetAddress> validIpList) {
-        ArrayList<InetAddress> resultIpList = new ArrayList<InetAddress>();
+    private List<InetAddress> removeDuplicateIp(List<InetAddress> validIpList) {
+        ArrayList<InetAddress> resultIpList = new ArrayList<>();
 
         for (InetAddress validIp : validIpList) {
             if (!resultIpList.contains(validIp)) {
@@ -653,9 +649,8 @@ public class EpdgSelector {
             @NonNull List<InetAddress> validIpList, @EpdgAddressOrder int order) {
         return switch (order) {
             case IPV4_PREFERRED -> validIpList.stream().sorted(inetAddressComparator).toList();
-            case IPV6_PREFERRED -> validIpList.stream()
-                    .sorted(inetAddressComparator.reversed())
-                    .toList();
+            case IPV6_PREFERRED ->
+                    validIpList.stream().sorted(inetAddressComparator.reversed()).toList();
             case SYSTEM_PREFERRED -> validIpList;
             default -> {
                 Log.w(TAG, "Invalid EpdgAddressOrder : " + order);
@@ -697,14 +692,13 @@ public class EpdgSelector {
 
         if (mTelephonyManager == null) {
             Log.e(TAG, "TelephonyManager is NULL");
-            return new ArrayList<String>();
+            return new ArrayList<>();
         } else {
             return mTelephonyManager.getEquivalentHomePlmns();
         }
     }
 
-    private void resolutionMethodStatic(
-            int filter, List<InetAddress> validIpList, Network network) {
+    private void resolveByStaticMethod(int filter, List<InetAddress> validIpList, Network network) {
         String[] domainNames = null;
 
         Log.d(TAG, "STATIC Method");
@@ -712,7 +706,7 @@ public class EpdgSelector {
         // Get the static domain names from carrier config
         // Config obtained in form of a list of domain names separated by
         // a delimiter is only used for testing purpose.
-        if (!inSameCountry()) {
+        if (isInVisitingCountry()) {
             domainNames =
                     getDomainNames(
                             CarrierConfigManager.Iwlan.KEY_EPDG_STATIC_ADDRESS_ROAMING_STRING);
@@ -727,7 +721,7 @@ public class EpdgSelector {
         }
 
         Log.d(TAG, "Static Domain Names: " + Arrays.toString(domainNames));
-        LinkedHashMap<String, List<InetAddress>> domainNameToIpAddr =
+        Map<String, List<InetAddress>> domainNameToIpAddr =
                 getIP(
                         Arrays.asList(domainNames),
                         filter,
@@ -746,8 +740,8 @@ public class EpdgSelector {
         return configValue.split(",");
     }
 
-    private boolean inSameCountry() {
-        boolean inSameCountry = true;
+    private boolean isInVisitingCountry() {
+        boolean isInAnotherCountry = true;
 
         TelephonyManager tm = mContext.getSystemService(TelephonyManager.class);
         tm =
@@ -759,24 +753,20 @@ public class EpdgSelector {
             String currentCountry = IwlanHelper.getLastKnownCountryCode(mContext);
             if (!TextUtils.isEmpty(simCountry) && !TextUtils.isEmpty(currentCountry)) {
                 Log.d(TAG, "simCountry = " + simCountry + ", currentCountry = " + currentCountry);
-                inSameCountry = simCountry.equalsIgnoreCase(currentCountry);
+                isInAnotherCountry = !simCountry.equalsIgnoreCase(currentCountry);
             }
         }
 
-        return inSameCountry;
+        return isInAnotherCountry;
     }
 
-    private Map<String, List<InetAddress>> resolutionMethodPlmn(
+    private Map<String, List<InetAddress>> resolveByPlmnBasedFqdn(
             int filter, List<InetAddress> validIpList, boolean isEmergency, Network network) {
-        String[] plmnList;
-        StringBuilder domainName = new StringBuilder();
-
         Log.d(TAG, "PLMN Method");
-
-        plmnList = getPlmnList();
-        List<String> domainNames = new ArrayList<>();
+        var plmnList = getPlmnList();
+        var domainNames = new ArrayList<String>();
         for (String plmn : plmnList) {
-            String[] mccmnc = splitMccMnc(plmn);
+            var mccmnc = splitMccMnc(plmn);
             /*
              * Operator Identifier based ePDG FQDN format:
              * epdg.epc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org
@@ -785,54 +775,38 @@ public class EpdgSelector {
              * sos.epdg.epc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org
              */
             if (isEmergency) {
-                domainName = new StringBuilder();
-                domainName
-                        .append("sos.")
-                        .append("epdg.epc.mnc")
-                        .append(mccmnc[1])
-                        .append(".mcc")
-                        .append(mccmnc[0])
-                        .append(".pub.3gppnetwork.org");
-                domainNames.add(domainName.toString());
-                domainName.setLength(0);
+                domainNames.add(
+                        "sos."
+                                + "epdg.epc.mnc"
+                                + mccmnc[1]
+                                + ".mcc"
+                                + mccmnc[0]
+                                + ".pub.3gppnetwork.org");
             }
             // For emergency PDN setup, still adding FQDN without "sos" header as second priority
             // because some operator doesn't support hostname with "sos" prefix.
-            domainName
-                    .append("epdg.epc.mnc")
-                    .append(mccmnc[1])
-                    .append(".mcc")
-                    .append(mccmnc[0])
-                    .append(".pub.3gppnetwork.org");
-            domainNames.add(domainName.toString());
-            domainName.setLength(0);
+            domainNames.add(
+                    "epdg.epc.mnc" + mccmnc[1] + ".mcc" + mccmnc[0] + ".pub.3gppnetwork.org");
         }
 
-        LinkedHashMap<String, List<InetAddress>> domainNameToIpAddr =
+        Map<String, List<InetAddress>> domainNameToIpAddr =
                 getIP(domainNames, filter, network, PARALLEL_PLMN_RESOLUTION_TIMEOUT_DURATION_SEC);
         printParallelDnsResult(domainNameToIpAddr);
         domainNameToIpAddr.values().forEach(validIpList::addAll);
         return domainNameToIpAddr;
     }
 
-    private void resolutionMethodCellularLoc(
+    private void resolveByTaiBasedFqdn(
             int filter, List<InetAddress> validIpList, boolean isEmergency, Network network) {
-        String[] plmnList;
-        StringBuilder domainName = new StringBuilder();
-
         Log.d(TAG, "CELLULAR_LOC Method");
 
-        TelephonyManager mTelephonyManager = mContext.getSystemService(TelephonyManager.class);
-        mTelephonyManager =
-                Objects.requireNonNull(mTelephonyManager)
-                        .createForSubscriptionId(IwlanHelper.getSubId(mContext, mSlotId));
-
-        if (mTelephonyManager == null) {
+        TelephonyManager telephonyManager = getTelephonyManager();
+        if (telephonyManager == null) {
             Log.e(TAG, "TelephonyManager is NULL");
             return;
         }
 
-        List<CellInfo> cellInfoList = mTelephonyManager.getAllCellInfo();
+        List<CellInfo> cellInfoList = telephonyManager.getAllCellInfo();
         if (cellInfoList == null) {
             Log.e(TAG, "cellInfoList is NULL");
             return;
@@ -843,162 +817,187 @@ public class EpdgSelector {
                 continue;
             }
 
-            if (cellInfo instanceof CellInfoGsm) {
-                CellIdentityGsm gsmCellId = ((CellInfoGsm) cellInfo).getCellIdentity();
-                String lacString = String.format("%04x", gsmCellId.getLac());
-
-                lacDomainNameResolution(filter, validIpList, lacString, isEmergency, network);
-            } else if (cellInfo instanceof CellInfoWcdma) {
-                CellIdentityWcdma wcdmaCellId = ((CellInfoWcdma) cellInfo).getCellIdentity();
-                String lacString = String.format("%04x", wcdmaCellId.getLac());
-
-                lacDomainNameResolution(filter, validIpList, lacString, isEmergency, network);
-            } else if (cellInfo instanceof CellInfoLte) {
-                CellIdentityLte lteCellId = ((CellInfoLte) cellInfo).getCellIdentity();
-                String tacString = String.format("%04x", lteCellId.getTac());
-                String[] tacSubString = new String[2];
-                tacSubString[0] = tacString.substring(0, 2);
-                tacSubString[1] = tacString.substring(2);
-
-                plmnList = getPlmnList();
-                for (String plmn : plmnList) {
-                    String[] mccmnc = splitMccMnc(plmn);
-                    /**
-                     * Tracking Area Identity based ePDG FQDN format:
-                     * tac-lb<TAC-low-byte>.tac-hb<TAC-high-byte>.tac.
-                     * epdg.epc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org
-                     *
-                     * <p>Tracking Area Identity based Emergency ePDG FQDN format:
-                     * tac-lb<TAC-low-byte>.tac-hb<TAC-highbyte>.tac.
-                     * sos.epdg.epc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org"
-                     */
-                    domainName
-                            .append("tac-lb")
-                            .append(tacSubString[1])
-                            .append(".tac-hb")
-                            .append(tacSubString[0]);
-                    if (isEmergency) {
-                        domainName.append(".tac.sos.epdg.epc.mnc");
-                    } else {
-                        domainName.append(".tac.epdg.epc.mnc");
-                    }
-                    domainName
-                            .append(mccmnc[1])
-                            .append(".mcc")
-                            .append(mccmnc[0])
-                            .append(".pub.3gppnetwork.org");
-                    getIP(domainName.toString(), filter, validIpList, network);
-                    domainName.setLength(0);
-                }
-            } else if (cellInfo instanceof CellInfoNr) {
-                CellIdentityNr nrCellId = (CellIdentityNr) cellInfo.getCellIdentity();
-                String tacString = String.format("%06x", nrCellId.getTac());
-                String[] tacSubString = new String[3];
-                tacSubString[0] = tacString.substring(0, 2);
-                tacSubString[1] = tacString.substring(2, 4);
-                tacSubString[2] = tacString.substring(4);
-
-                plmnList = getPlmnList();
-                for (String plmn : plmnList) {
-                    String[] mccmnc = splitMccMnc(plmn);
-                    /**
-                     * 5GS Tracking Area Identity based ePDG FQDN format:
-                     * tac-lb<TAC-low-byte>.tac-mb<TAC-middle-byte>.tac-hb<TAC-high-byte>.
-                     * 5gstac.epdg.epc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org
-                     *
-                     * <p>5GS Tracking Area Identity based Emergency ePDG FQDN format:
-                     * tac-lb<TAC-low-byte>.tac-mb<TAC-middle-byte>.tac-hb<TAC-high-byte>.
-                     * 5gstac.sos.epdg.epc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org
-                     */
-                    domainName
-                            .append("tac-lb")
-                            .append(tacSubString[2])
-                            .append(".tac-mb")
-                            .append(tacSubString[1])
-                            .append(".tac-hb")
-                            .append(tacSubString[0]);
-                    if (isEmergency) {
-                        domainName.append(".5gstac.sos.epdg.epc.mnc");
-                    } else {
-                        domainName.append(".5gstac.epdg.epc.mnc");
-                    }
-                    domainName
-                            .append(mccmnc[1])
-                            .append(".mcc")
-                            .append(mccmnc[0])
-                            .append(".pub.3gppnetwork.org");
-                    getIP(domainName.toString(), filter, validIpList, network);
-                    domainName.setLength(0);
-                }
+            if (cellInfo instanceof CellInfoGsm cellInfoGsm) {
+                handleGsmCellInfo(cellInfoGsm, filter, validIpList, isEmergency, network);
+            } else if (cellInfo instanceof CellInfoWcdma cellInfoWcdma) {
+                handleWcdmaCellInfo(cellInfoWcdma, filter, validIpList, isEmergency, network);
+            } else if (cellInfo instanceof CellInfoLte cellInfoLte) {
+                handleLteCellInfo(cellInfoLte, filter, validIpList, isEmergency, network);
+            } else if (cellInfo instanceof CellInfoNr cellInfoNr) {
+                handleNrCellInfo(cellInfoNr, filter, validIpList, isEmergency, network);
             } else {
                 Log.d(TAG, "This cell doesn't contain LAC/TAC info");
             }
         }
     }
 
+    private void handleGsmCellInfo(
+            CellInfoGsm cellInfoGsm,
+            int filter,
+            List<InetAddress> validIpList,
+            boolean isEmergency,
+            Network network) {
+        var gsmCellId = cellInfoGsm.getCellIdentity();
+        var lacString = String.format("%04x", gsmCellId.getLac());
+        lacDomainNameResolution(filter, validIpList, lacString, isEmergency, network);
+    }
+
+    private void handleWcdmaCellInfo(
+            CellInfoWcdma cellInfoWcdma,
+            int filter,
+            List<InetAddress> validIpList,
+            boolean isEmergency,
+            Network network) {
+        var wcdmaCellId = cellInfoWcdma.getCellIdentity();
+        var lacString = String.format("%04x", wcdmaCellId.getLac());
+        lacDomainNameResolution(filter, validIpList, lacString, isEmergency, network);
+    }
+
+    private void handleLteCellInfo(
+            CellInfoLte cellInfoLte,
+            int filter,
+            List<InetAddress> validIpList,
+            boolean isEmergency,
+            Network network) {
+        var plmnList = getPlmnList();
+        var lteCellId = cellInfoLte.getCellIdentity();
+        var tacString = String.format("%04x", lteCellId.getTac());
+        var tacSubString = List.of(tacString.substring(0, 2), tacString.substring(2));
+
+        for (String plmn : plmnList) {
+            var mccmnc = splitMccMnc(plmn);
+            /*
+             * Tracking Area Identity based ePDG FQDN format:
+             * tac-lb<TAC-low-byte>.tac-hb<TAC-high-byte>.tac.
+             * epdg.epc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org
+             *
+             * <p>Tracking Area Identity based Emergency ePDG FQDN format:
+             * tac-lb<TAC-low-byte>.tac-hb<TAC-highbyte>.tac.
+             * sos.epdg.epc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org"
+             */
+            String domainName =
+                    "tac-lb"
+                            + tacSubString.get(1)
+                            + ".tac-hb"
+                            + tacSubString.getFirst()
+                            + (isEmergency ? ".tac.sos.epdg.epc.mnc" : ".tac.epdg.epc.mnc")
+                            + mccmnc[1]
+                            + ".mcc"
+                            + mccmnc[0]
+                            + ".pub.3gppnetwork.org";
+            getIP(domainName, filter, validIpList, network);
+        }
+    }
+
+    private void handleNrCellInfo(
+            CellInfoNr cellInfoNr,
+            int filter,
+            List<InetAddress> validIpList,
+            boolean isEmergency,
+            Network network) {
+        var nrCellId = (CellIdentityNr) cellInfoNr.getCellIdentity();
+        var tacString = String.format("%06x", nrCellId.getTac());
+        var tacSubString =
+                List.of(
+                        tacString.substring(0, 2),
+                        tacString.substring(2, 4),
+                        tacString.substring(4));
+        var plmnList = getPlmnList();
+        for (String plmn : plmnList) {
+            var mccmnc = splitMccMnc(plmn);
+            /*
+             * 5GS Tracking Area Identity based ePDG FQDN format:
+             * tac-lb<TAC-low-byte>.tac-mb<TAC-middle-byte>.tac-hb<TAC-high-byte>.
+             * 5gstac.epdg.epc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org
+             *
+             * <p>5GS Tracking Area Identity based Emergency ePDG FQDN format:
+             * tac-lb<TAC-low-byte>.tac-mb<TAC-middle-byte>.tac-hb<TAC-high-byte>.
+             * 5gstac.sos.epdg.epc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org
+             */
+            String domainName =
+                    "tac-lb"
+                            + tacSubString.get(2)
+                            + ".tac-mb"
+                            + tacSubString.get(1)
+                            + ".tac-hb"
+                            + tacSubString.getFirst()
+                            + (isEmergency ? ".5gstac.sos.epdg.epc.mnc" : ".5gstac.epdg.epc.mnc")
+                            + mccmnc[1]
+                            + ".mcc"
+                            + mccmnc[0]
+                            + ".pub.3gppnetwork.org";
+            getIP(domainName, filter, validIpList, network);
+        }
+    }
+
+    private @androidx.annotation.Nullable TelephonyManager getTelephonyManager() {
+        TelephonyManager telephonyManager = mContext.getSystemService(TelephonyManager.class);
+        telephonyManager =
+                Objects.requireNonNull(telephonyManager)
+                        .createForSubscriptionId(IwlanHelper.getSubId(mContext, mSlotId));
+
+        if (telephonyManager == null) {
+            Log.e(TAG, "TelephonyManager is NULL");
+            return null;
+        }
+        return telephonyManager;
+    }
+
     private void lacDomainNameResolution(
             int filter,
             List<InetAddress> validIpList,
             String lacString,
             boolean isEmergency,
             Network network) {
-        String[] plmnList;
-        StringBuilder domainName = new StringBuilder();
-
-        plmnList = getPlmnList();
+        var plmnList = getPlmnList();
         for (String plmn : plmnList) {
-            String[] mccmnc = splitMccMnc(plmn);
-            /**
+            var mccmnc = splitMccMnc(plmn);
+            /*
              * Location Area Identity based ePDG FQDN format:
              * lac<LAC>.epdg.epc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org
              *
              * <p>Location Area Identity based Emergency ePDG FQDN format:
              * lac<LAC>.sos.epdg.epc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org
              */
-            domainName.append("lac").append(lacString);
-            if (isEmergency) {
-                domainName.append(".sos.epdg.epc.mnc");
-            } else {
-                domainName.append(".epdg.epc.mnc");
-            }
-            domainName
-                    .append(mccmnc[1])
-                    .append(".mcc")
-                    .append(mccmnc[0])
-                    .append(".pub.3gppnetwork.org");
-
-            getIP(domainName.toString(), filter, validIpList, network);
-            domainName.setLength(0);
+            var domainName =
+                    "lac"
+                            + lacString
+                            + (isEmergency ? ".sos.epdg.epc.mnc" : ".epdg.epc.mnc")
+                            + mccmnc[1]
+                            + ".mcc"
+                            + mccmnc[0]
+                            + ".pub.3gppnetwork.org";
+            getIP(domainName, filter, validIpList, network);
         }
     }
 
-    private void resolutionMethodPco(int filter, @NonNull List<InetAddress> validIpList) {
+    private void resolveByPcoMethod(int filter, @NonNull List<InetAddress> validIpList) {
         Log.d(TAG, "PCO Method");
 
-        int PCO_ID_IPV6 =
+        // TODO(b/362299669): Refactor PCO clean up upon SIM changed.
+        int epdgIPv6PcoId =
                 IwlanCarrierConfig.getConfigInt(
                         mContext, mSlotId, CarrierConfigManager.Iwlan.KEY_EPDG_PCO_ID_IPV6_INT);
-        int PCO_ID_IPV4 =
+        int epdgIPv4PcoId =
                 IwlanCarrierConfig.getConfigInt(
                         mContext, mSlotId, CarrierConfigManager.Iwlan.KEY_EPDG_PCO_ID_IPV4_INT);
-
         switch (filter) {
             case PROTO_FILTER_IPV4:
-                if (mV4PcoId != PCO_ID_IPV4) {
+                if (mV4PcoId != epdgIPv4PcoId) {
                     clearPcoData();
                 } else {
                     getInetAddressWithPcoData(mV4PcoData, validIpList);
                 }
                 break;
             case PROTO_FILTER_IPV6:
-                if (mV6PcoId != PCO_ID_IPV6) {
+                if (mV6PcoId != epdgIPv6PcoId) {
                     clearPcoData();
                 } else {
                     getInetAddressWithPcoData(mV6PcoData, validIpList);
                 }
                 break;
             case PROTO_FILTER_IPV4V6:
-                if ((mV4PcoId != PCO_ID_IPV4) || (mV6PcoId != PCO_ID_IPV6)) {
+                if ((mV4PcoId != epdgIPv4PcoId) || (mV6PcoId != epdgIPv6PcoId)) {
                     clearPcoData();
                 } else {
                     getInetAddressWithPcoData(mV4PcoData, validIpList);
@@ -1042,8 +1041,6 @@ public class EpdgSelector {
     }
 
     private String composeFqdnWithMccMnc(String mcc, String mnc, boolean isEmergency) {
-        StringBuilder domainName = new StringBuilder();
-
         /*
          * Operator Identifier based ePDG FQDN format:
          * epdg.epc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org
@@ -1051,18 +1048,12 @@ public class EpdgSelector {
          * Operator Identifier based Emergency ePDG FQDN format:
          * sos.epdg.epc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org
          */
-        domainName.setLength(0);
-        if (isEmergency) {
-            domainName.append("sos.");
-        }
-        domainName
-                .append("epdg.epc.mnc")
-                .append(mnc)
-                .append(".mcc")
-                .append(mcc)
-                .append(".pub.3gppnetwork.org");
-
-        return domainName.toString();
+        return (isEmergency ? "sos." : "")
+                + "epdg.epc.mnc"
+                + mnc
+                + ".mcc"
+                + mcc
+                + ".pub.3gppnetwork.org";
     }
 
     private boolean isRegisteredWith3GPP(TelephonyManager telephonyManager) {
@@ -1139,19 +1130,10 @@ public class EpdgSelector {
         }
     }
 
-    private void resolutionMethodVisitedCountry(
+    private void resolveMethodVisitedCountry(
             int filter, List<InetAddress> validIpList, boolean isEmergency, Network network) {
-        StringBuilder domainName = new StringBuilder();
-
-        TelephonyManager telephonyManager = mContext.getSystemService(TelephonyManager.class);
-        telephonyManager =
-                Objects.requireNonNull(telephonyManager)
-                        .createForSubscriptionId(IwlanHelper.getSubId(mContext, mSlotId));
-
-        if (telephonyManager == null) {
-            Log.e(TAG, "TelephonyManager is NULL");
-            return;
-        }
+        TelephonyManager telephonyManager = getTelephonyManager();
+        if (telephonyManager == null) return;
 
         final boolean isRegisteredWith3GPP = isRegisteredWith3GPP(telephonyManager);
 
@@ -1188,22 +1170,19 @@ public class EpdgSelector {
          * Visited Country Emergency ePDG FQDN format:
          * sos.epdg.epc.mcc<MCC>.visited-country.pub.3gppnetwork.org
          */
-        if (isEmergency) {
-            domainName.append("sos.");
-        }
-        domainName
-                .append("epdg.epc.mcc")
-                .append(cellMcc)
-                .append(".visited-country.pub.3gppnetwork.org");
-
+        var domainName =
+                (isEmergency ? "sos." : "")
+                        + "epdg.epc.mcc"
+                        + cellMcc
+                        + ".visited-country.pub.3gppnetwork.org";
         Log.d(TAG, "Visited Country FQDN with " + domainName);
 
         CompletableFuture<List<NaptrTarget>> naptrDnsResult = new CompletableFuture<>();
         DnsResolver.Callback<List<NaptrTarget>> naptrDnsCb =
-                new DnsResolver.Callback<List<NaptrTarget>>() {
+                new DnsResolver.Callback<>() {
                     @Override
                     public void onAnswer(@NonNull final List<NaptrTarget> answer, final int rcode) {
-                        if (rcode == 0 && answer.size() != 0) {
+                        if (rcode == 0 && !answer.isEmpty()) {
                             naptrDnsResult.complete(answer);
                         } else {
                             naptrDnsResult.completeExceptionally(new UnknownHostException());
@@ -1215,13 +1194,13 @@ public class EpdgSelector {
                         naptrDnsResult.completeExceptionally(error);
                     }
                 };
-        NaptrDnsResolver.query(network, domainName.toString(), Runnable::run, null, naptrDnsCb);
+        NaptrDnsResolver.query(network, domainName, Runnable::run, null, naptrDnsCb);
 
         try {
             final List<NaptrTarget> naptrResponse =
                     naptrDnsResult.get(DNS_RESOLVER_TIMEOUT_DURATION_SEC, TimeUnit.SECONDS);
             // Check if there is any record in the NAPTR response
-            if (naptrResponse != null && naptrResponse.size() > 0) {
+            if (naptrResponse != null && !naptrResponse.isEmpty()) {
                 processNaptrResponse(
                         filter,
                         validIpList,
@@ -1281,7 +1260,7 @@ public class EpdgSelector {
      * @param selectorCallback {@link EpdgSelectorCallback} The result will be returned through this
      *     callback. If null, the caller is not interested in the result. Typically, this means the
      *     caller is performing DNS prefetch of the ePDG server addresses to warm the native
-     *     dnsresolver module's caches.
+     *     dnsResolver module's caches.
      * @return {link IwlanError} denoting the status of this operation.
      */
     public IwlanError getValidatedServerList(
@@ -1320,30 +1299,29 @@ public class EpdgSelector {
                                                                     .EPDG_ADDRESS_VISITED_COUNTRY);
 
                     // In the visited country
-                    if (isRoaming && !inSameCountry() && isVisitedCountryMethodRequired) {
-                        resolutionMethodVisitedCountry(filter, validIpList, isEmergency, network);
+                    if (isRoaming && isInVisitingCountry() && isVisitedCountryMethodRequired) {
+                        resolveMethodVisitedCountry(filter, validIpList, isEmergency, network);
                     }
 
                     Map<String, List<InetAddress>> plmnDomainNamesToIpAddress = null;
                     for (int addrResolutionMethod : addrResolutionMethods) {
                         switch (addrResolutionMethod) {
                             case CarrierConfigManager.Iwlan.EPDG_ADDRESS_STATIC:
-                                resolutionMethodStatic(filter, validIpList, network);
+                                resolveByStaticMethod(filter, validIpList, network);
                                 break;
 
                             case CarrierConfigManager.Iwlan.EPDG_ADDRESS_PLMN:
                                 plmnDomainNamesToIpAddress =
-                                        resolutionMethodPlmn(
+                                        resolveByPlmnBasedFqdn(
                                                 filter, validIpList, isEmergency, network);
                                 break;
 
                             case CarrierConfigManager.Iwlan.EPDG_ADDRESS_PCO:
-                                resolutionMethodPco(filter, validIpList);
+                                resolveByPcoMethod(filter, validIpList);
                                 break;
 
                             case CarrierConfigManager.Iwlan.EPDG_ADDRESS_CELLULAR_LOC:
-                                resolutionMethodCellularLoc(
-                                        filter, validIpList, isEmergency, network);
+                                resolveByTaiBasedFqdn(filter, validIpList, isEmergency, network);
                                 break;
 
                             default:
@@ -1405,4 +1383,46 @@ public class EpdgSelector {
     private static boolean isValidPlmn(String plmn) {
         return plmn != null && PLMN_PATTERN.matcher(plmn).matches();
     }
+
+    @VisibleForTesting
+    void processCarrierSignalPcoValue(Intent intent) {
+        int apnBitMask = intent.getIntExtra(TelephonyManager.EXTRA_APN_TYPE, 0);
+        int pcoId = intent.getIntExtra(TelephonyManager.EXTRA_PCO_ID, 0);
+        byte[] pcoData = intent.getByteArrayExtra(TelephonyManager.EXTRA_PCO_VALUE);
+        if ((apnBitMask & ApnSetting.TYPE_IMS) == 0) {
+            Log.d(TAG, "Unwanted ApnType for PCO: " + apnBitMask);
+            return;
+        }
+        if (pcoData == null) {
+            Log.e(TAG, "PCO data unavailable");
+            return;
+        }
+        Log.d(
+                TAG,
+                "Received PCO ID:"
+                        + String.format("0x%04x", pcoId)
+                        + ", PcoData:"
+                        + Arrays.toString(pcoData));
+        int epdgIPv6PcoId =
+                IwlanCarrierConfig.getConfigInt(
+                        mContext, mSlotId, CarrierConfigManager.Iwlan.KEY_EPDG_PCO_ID_IPV6_INT);
+        int epdgIPv4PcoId =
+                IwlanCarrierConfig.getConfigInt(
+                        mContext, mSlotId, CarrierConfigManager.Iwlan.KEY_EPDG_PCO_ID_IPV4_INT);
+        Log.d(
+                TAG,
+                "PCO_ID_IPv6:"
+                        + String.format("0x%04x", epdgIPv6PcoId)
+                        + ", PCO_ID_IPv4:"
+                        + String.format("0x%04x", epdgIPv4PcoId));
+        if (pcoId == epdgIPv4PcoId) {
+            mV4PcoId = pcoId;
+            mV4PcoData.add(pcoData);
+        } else if (pcoId == epdgIPv6PcoId) {
+            mV6PcoId = pcoId;
+            mV6PcoData.add(pcoData);
+        } else {
+            Log.d(TAG, "Unwanted PcoID " + pcoId);
+        }
+    }
 }
diff --git a/src/com/google/android/iwlan/epdg/EpdgTunnelManager.java b/src/com/google/android/iwlan/epdg/EpdgTunnelManager.java
index 05d6374..ab30c33 100644
--- a/src/com/google/android/iwlan/epdg/EpdgTunnelManager.java
+++ b/src/com/google/android/iwlan/epdg/EpdgTunnelManager.java
@@ -23,7 +23,12 @@ import static android.system.OsConstants.AF_INET;
 import static android.system.OsConstants.AF_INET6;
 import static android.telephony.PreciseDataConnectionState.NetworkValidationStatus;
 
+import static com.google.android.iwlan.proto.MetricsAtom.*;
+
 import android.content.Context;
+import android.net.ConnectivityDiagnosticsManager;
+import android.net.ConnectivityDiagnosticsManager.ConnectivityDiagnosticsCallback;
+import android.net.ConnectivityDiagnosticsManager.ConnectivityReport;
 import android.net.ConnectivityManager;
 import android.net.InetAddresses;
 import android.net.IpPrefix;
@@ -33,6 +38,7 @@ import android.net.LinkAddress;
 import android.net.LinkProperties;
 import android.net.Network;
 import android.net.NetworkCapabilities;
+import android.net.NetworkRequest;
 import android.net.eap.EapAkaInfo;
 import android.net.eap.EapInfo;
 import android.net.eap.EapSessionConfig;
@@ -62,6 +68,7 @@ import android.net.ipsec.ike.ike3gpp.Ike3gppExtension;
 import android.net.ipsec.ike.ike3gpp.Ike3gppN1ModeInformation;
 import android.net.ipsec.ike.ike3gpp.Ike3gppParams;
 import android.os.Handler;
+import android.os.HandlerExecutor;
 import android.os.HandlerThread;
 import android.os.Looper;
 import android.os.Message;
@@ -82,13 +89,13 @@ import com.google.android.iwlan.ErrorPolicyManager;
 import com.google.android.iwlan.IwlanCarrierConfig;
 import com.google.android.iwlan.IwlanError;
 import com.google.android.iwlan.IwlanHelper;
-import com.google.android.iwlan.IwlanTunnelMetricsImpl;
-import com.google.android.iwlan.TunnelMetricsInterface;
+import com.google.android.iwlan.IwlanStatsLog;
 import com.google.android.iwlan.TunnelMetricsInterface.OnClosedMetrics;
 import com.google.android.iwlan.TunnelMetricsInterface.OnOpenedMetrics;
 import com.google.android.iwlan.exceptions.IwlanSimNotReadyException;
 import com.google.android.iwlan.flags.FeatureFlags;
 import com.google.android.iwlan.flags.FeatureFlagsImpl;
+import com.google.android.iwlan.proto.MetricsAtom;
 
 import java.io.IOException;
 import java.io.PrintWriter;
@@ -114,6 +121,7 @@ public class EpdgTunnelManager {
     private final Context mContext;
     private final int mSlotId;
     private Handler mHandler;
+    private ConnectivityDiagnosticsCallback mConnectivityDiagnosticsCallback;
 
     private static final int EVENT_TUNNEL_BRINGUP_REQUEST = 0;
     private static final int EVENT_TUNNEL_BRINGDOWN_REQUEST = 1;
@@ -157,11 +165,17 @@ public class EpdgTunnelManager {
     private static final String TRAFFIC_SELECTOR_IPV6_END_ADDR =
             "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
 
+    private static final int NETWORK_VALIDATION_MIN_INTERVAL_MS = 10000;
+
+    private static long sLastUnderlyingNetworkValidationMs = 0;
+    private static final Object sLastUnderlyingNetworkValidationLock = new Object();
+
     // "192.0.2.0" is selected from RFC5737, "IPv4 Address Blocks Reserved for Documentation"
     private static final InetAddress DUMMY_ADDR = InetAddresses.parseNumericAddress("192.0.2.0");
 
     private static final Map<Integer, EpdgTunnelManager> mTunnelManagerInstances =
             new ConcurrentHashMap<>();
+    private final Map<Network, MetricsAtom> mMetricsAtomForNetwork = new ConcurrentHashMap<>();
 
     private final Queue<TunnelRequestWrapper> mPendingBringUpRequests = new ArrayDeque<>();
 
@@ -176,6 +190,7 @@ public class EpdgTunnelManager {
     private boolean mHasConnectedToEpdg;
     private final IkeSessionCreator mIkeSessionCreator;
     private final IpSecManager mIpSecManager;
+    private final EpdgSelector mEpdgSelector;
 
     private final Map<String, TunnelConfig> mApnNameToTunnelConfig = new ConcurrentHashMap<>();
     private final Map<String, Integer> mApnNameToCurrentToken = new ConcurrentHashMap<>();
@@ -264,24 +279,17 @@ public class EpdgTunnelManager {
     public @interface TunnelBringDownReason {}
 
     private static String bringdownReasonToString(@TunnelBringDownReason int reason) {
-        switch (reason) {
-            case BRINGDOWN_REASON_UNKNOWN:
-                return "BRINGDOWN_REASON_UNKNOWN";
-            case BRINGDOWN_REASON_DISABLE_N1_MODE:
-                return "BRINGDOWN_REASON_DISABLE_N1_MODE";
-            case BRINGDOWN_REASON_ENABLE_N1_MODE:
-                return "BRINGDOWN_REASON_ENABLE_N1_MODE";
-            case BRINGDOWN_REASON_SERVICE_OUT_OF_SYNC:
-                return "BRINGDOWN_REASON_SERVICE_OUT_OF_SYNC";
-            case BRINGDOWN_REASON_IN_DEACTIVATING_STATE:
-                return "BRINGDOWN_REASON_IN_DEACTIVATING_STATE";
-            case BRINGDOWN_REASON_NETWORK_UPDATE_WHEN_TUNNEL_IN_BRINGUP:
-                return "BRINGDOWN_REASON_NETWORK_UPDATE_WHEN_TUNNEL_IN_BRINGUP";
-            case BRINGDOWN_REASON_DEACTIVATE_DATA_CALL:
-                return "BRINGDOWN_REASON_DEACTIVATE_DATA_CALL";
-            default:
-                return "Unknown(" + reason + ")";
-        }
+        return switch (reason) {
+            case BRINGDOWN_REASON_UNKNOWN -> "BRINGDOWN_REASON_UNKNOWN";
+            case BRINGDOWN_REASON_DISABLE_N1_MODE -> "BRINGDOWN_REASON_DISABLE_N1_MODE";
+            case BRINGDOWN_REASON_ENABLE_N1_MODE -> "BRINGDOWN_REASON_ENABLE_N1_MODE";
+            case BRINGDOWN_REASON_SERVICE_OUT_OF_SYNC -> "BRINGDOWN_REASON_SERVICE_OUT_OF_SYNC";
+            case BRINGDOWN_REASON_IN_DEACTIVATING_STATE -> "BRINGDOWN_REASON_IN_DEACTIVATING_STATE";
+            case BRINGDOWN_REASON_NETWORK_UPDATE_WHEN_TUNNEL_IN_BRINGUP ->
+                    "BRINGDOWN_REASON_NETWORK_UPDATE_WHEN_TUNNEL_IN_BRINGUP";
+            case BRINGDOWN_REASON_DEACTIVATE_DATA_CALL -> "BRINGDOWN_REASON_DEACTIVATE_DATA_CALL";
+            default -> "Unknown(" + reason + ")";
+        };
     }
 
     private final EpdgSelector.EpdgSelectorCallback mSelectorCallback =
@@ -301,7 +309,6 @@ public class EpdgTunnelManager {
     @VisibleForTesting
     class TunnelConfig {
         @NonNull final TunnelCallback mTunnelCallback;
-        @NonNull final TunnelMetricsInterface mTunnelMetrics;
         // TODO: Change this to TunnelLinkProperties after removing autovalue
         private List<InetAddress> mPcscfAddrList;
         private List<InetAddress> mDnsAddrList;
@@ -324,14 +331,12 @@ public class EpdgTunnelManager {
         public TunnelConfig(
                 IkeSession ikeSession,
                 TunnelCallback tunnelCallback,
-                TunnelMetricsInterface tunnelMetrics,
                 IpSecManager.IpSecTunnelInterface iface,
                 InetAddress srcIpv6Addr,
                 int srcIpv6PrefixLength,
                 boolean isEmergency,
                 InetAddress epdgAddress) {
             mTunnelCallback = tunnelCallback;
-            mTunnelMetrics = tunnelMetrics;
             mIkeSession = ikeSession;
             mError = new IwlanError(IwlanError.NO_ERROR);
             mSrcIpv6Address = srcIpv6Addr;
@@ -376,11 +381,6 @@ public class EpdgTunnelManager {
             return mTunnelCallback;
         }
 
-        @NonNull
-        TunnelMetricsInterface getTunnelMetrics() {
-            return mTunnelMetrics;
-        }
-
         List<InetAddress> getPcscfAddrList() {
             return mPcscfAddrList;
         }
@@ -503,19 +503,19 @@ public class EpdgTunnelManager {
         @Override
         public void onOpened(IkeSessionConfiguration sessionConfiguration) {
             Log.d(TAG, "Ike session opened for apn: " + mApnName + " with token: " + mToken);
-            mHandler.sendMessage(
-                    mHandler.obtainMessage(
+            mHandler.obtainMessage(
                             EVENT_IKE_SESSION_OPENED,
-                            new IkeSessionOpenedData(mApnName, mToken, sessionConfiguration)));
+                            new IkeSessionOpenedData(mApnName, mToken, sessionConfiguration))
+                    .sendToTarget();
         }
 
         @Override
         public void onClosed() {
             Log.d(TAG, "Ike session closed for apn: " + mApnName + " with token: " + mToken);
-            mHandler.sendMessage(
-                    mHandler.obtainMessage(
+            mHandler.obtainMessage(
                             EVENT_IKE_SESSION_CLOSED,
-                            new SessionClosedData(mApnName, mToken, null /* ikeException */)));
+                            new SessionClosedData(mApnName, mToken, null /* ikeException */))
+                    .sendToTarget();
         }
 
         @Override
@@ -550,11 +550,11 @@ public class EpdgTunnelManager {
                             + mToken
                             + " Network: "
                             + network);
-            mHandler.sendMessage(
-                    mHandler.obtainMessage(
+            mHandler.obtainMessage(
                             EVENT_IKE_SESSION_CONNECTION_INFO_CHANGED,
                             new IkeSessionConnectionInfoData(
-                                    mApnName, mToken, ikeSessionConnectionInfo)));
+                                    mApnName, mToken, ikeSessionConnectionInfo))
+                    .sendToTarget();
         }
 
         @Override
@@ -599,10 +599,10 @@ public class EpdgTunnelManager {
 
         @Override
         public void onIke3gppDataReceived(List<Ike3gppData> payloads) {
-            mHandler.sendMessage(
-                    mHandler.obtainMessage(
+            mHandler.obtainMessage(
                             EVENT_IKE_3GPP_DATA_RECEIVED,
-                            new Ike3gppDataReceived(mApnName, mToken, payloads)));
+                            new Ike3gppDataReceived(mApnName, mToken, payloads))
+                    .sendToTarget();
         }
     }
 
@@ -620,23 +620,23 @@ public class EpdgTunnelManager {
         @Override
         public void onOpened(ChildSessionConfiguration sessionConfiguration) {
             Log.d(TAG, "onOpened child session for apn: " + mApnName + " with token: " + mToken);
-            mHandler.sendMessage(
-                    mHandler.obtainMessage(
+            mHandler.obtainMessage(
                             EVENT_CHILD_SESSION_OPENED,
                             new TunnelOpenedData(
                                     mApnName,
                                     mToken,
                                     sessionConfiguration.getInternalDnsServers(),
-                                    sessionConfiguration.getInternalAddresses())));
+                                    sessionConfiguration.getInternalAddresses()))
+                    .sendToTarget();
         }
 
         @Override
         public void onClosed() {
             Log.d(TAG, "onClosed child session for apn: " + mApnName + " with token: " + mToken);
-            mHandler.sendMessage(
-                    mHandler.obtainMessage(
+            mHandler.obtainMessage(
                             EVENT_CHILD_SESSION_CLOSED,
-                            new SessionClosedData(mApnName, mToken, null /* ikeException */)));
+                            new SessionClosedData(mApnName, mToken, null /* ikeException */))
+                    .sendToTarget();
         }
 
         @Override
@@ -649,22 +649,19 @@ public class EpdgTunnelManager {
                 IpSecTransform inIpSecTransform, IpSecTransform outIpSecTransform) {
             // migration is similar to addition
             Log.d(TAG, "Transforms migrated for apn: " + mApnName + " with token: " + mToken);
-            mHandler.sendMessage(
-                    mHandler.obtainMessage(
+            mHandler.obtainMessage(
                             EVENT_IPSEC_TRANSFORM_CREATED,
                             new IpsecTransformData(
-                                    inIpSecTransform,
-                                    IpSecManager.DIRECTION_IN,
-                                    mApnName,
-                                    mToken)));
-            mHandler.sendMessage(
-                    mHandler.obtainMessage(
+                                    inIpSecTransform, IpSecManager.DIRECTION_IN, mApnName, mToken))
+                    .sendToTarget();
+            mHandler.obtainMessage(
                             EVENT_IPSEC_TRANSFORM_CREATED,
                             new IpsecTransformData(
                                     outIpSecTransform,
                                     IpSecManager.DIRECTION_OUT,
                                     mApnName,
-                                    mToken)));
+                                    mToken))
+                    .sendToTarget();
         }
 
         @Override
@@ -677,10 +674,10 @@ public class EpdgTunnelManager {
                             + mApnName
                             + ", token: "
                             + mToken);
-            mHandler.sendMessage(
-                    mHandler.obtainMessage(
+            mHandler.obtainMessage(
                             EVENT_IPSEC_TRANSFORM_CREATED,
-                            new IpsecTransformData(ipSecTransform, direction, mApnName, mToken)));
+                            new IpsecTransformData(ipSecTransform, direction, mApnName, mToken))
+                    .sendToTarget();
         }
 
         @Override
@@ -693,10 +690,10 @@ public class EpdgTunnelManager {
                             + mApnName
                             + ", token: "
                             + mToken);
-            mHandler.sendMessage(
-                    mHandler.obtainMessage(
+            mHandler.obtainMessage(
                             EVENT_IPSEC_TRANSFORM_DELETED,
-                            new IpsecTransformData(ipSecTransform, direction, mApnName, mToken)));
+                            new IpsecTransformData(ipSecTransform, direction, mApnName, mToken))
+                    .sendToTarget();
         }
     }
 
@@ -707,8 +704,78 @@ public class EpdgTunnelManager {
         mFeatureFlags = featureFlags;
         mIkeSessionCreator = new IkeSessionCreator();
         mIpSecManager = mContext.getSystemService(IpSecManager.class);
+        // Adding this here is necessary because we need to initialize EpdgSelector at the beginning
+        // to ensure no broadcasts are missed.
+        mEpdgSelector = EpdgSelector.getSelectorInstance(mContext, mSlotId);
         TAG = EpdgTunnelManager.class.getSimpleName() + "[" + mSlotId + "]";
         initHandler();
+        registerConnectivityDiagnosticsCallback();
+    }
+
+    private void registerConnectivityDiagnosticsCallback() {
+        ConnectivityDiagnosticsManager connectivityDiagnosticsManager =
+                Objects.requireNonNull(mContext)
+                        .getSystemService(ConnectivityDiagnosticsManager.class);
+        NetworkRequest networkRequest =
+                new NetworkRequest.Builder()
+                        .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
+                        .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
+                        .build();
+        mConnectivityDiagnosticsCallback =
+                new ConnectivityDiagnosticsCallback() {
+                    @Override
+                    public void onConnectivityReportAvailable(@NonNull ConnectivityReport report) {
+                        Network network = report.getNetwork();
+                        int mNetworkValidationResult =
+                                report.getAdditionalInfo()
+                                        .getInt(ConnectivityReport.KEY_NETWORK_VALIDATION_RESULT);
+                        if (!mMetricsAtomForNetwork.containsKey(network)) {
+                            return;
+                        }
+                        reportValidationMetricsAtom(
+                                network, getMetricsValidationResult(mNetworkValidationResult));
+                    }
+                };
+        connectivityDiagnosticsManager.registerConnectivityDiagnosticsCallback(
+                networkRequest, new HandlerExecutor(mHandler), mConnectivityDiagnosticsCallback);
+    }
+
+    private void reportValidationMetricsAtom(Network network, int validationResult) {
+        if (!mMetricsAtomForNetwork.containsKey(network)) {
+            return;
+        }
+        MetricsAtom metricsAtom = mMetricsAtomForNetwork.get(network);
+        metricsAtom.setValidationResult(validationResult);
+        metricsAtom.setValidationDurationMills(
+                (int) (IwlanHelper.elapsedRealtime() - metricsAtom.getValidationStartTimeMills()));
+
+        Log.d(
+                TAG,
+                "reportValidationMetricsAtom: reason="
+                        + metricsAtom.getTriggerReason()
+                        + " validationResult="
+                        + metricsAtom.getValidationResult()
+                        + " transportType="
+                        + metricsAtom.getValidationTransportType()
+                        + " duration="
+                        + metricsAtom.getValidationDurationMills());
+        metricsAtom.sendMetricsData();
+        mMetricsAtomForNetwork.remove(network);
+    }
+
+    @VisibleForTesting
+    MetricsAtom getValidationMetricsAtom(Network network) {
+        return mMetricsAtomForNetwork.get(network);
+    }
+
+    private void unregisterConnectivityDiagnosticsCallback() {
+        ConnectivityDiagnosticsManager connectivityDiagnosticsManager =
+                Objects.requireNonNull(mContext)
+                        .getSystemService(ConnectivityDiagnosticsManager.class);
+        if (connectivityDiagnosticsManager != null) {
+            connectivityDiagnosticsManager.unregisterConnectivityDiagnosticsCallback(
+                    mConnectivityDiagnosticsCallback);
+        }
     }
 
     @VisibleForTesting
@@ -726,18 +793,19 @@ public class EpdgTunnelManager {
     /**
      * Gets a EpdgTunnelManager instance.
      *
-     * @param context application context
-     * @param subId subscription ID for the tunnel
-     * @return tunnel manager instance corresponding to the sub id
+     * @param context the context at which EpdgTunnelManager instance to be created
+     * @param slotId the slot index at which EpdgTunnelManager instance to be created
+     * @return EpdgTunnelManager instance for the specified slot id
      */
-    public static EpdgTunnelManager getInstance(@NonNull Context context, int subId) {
+    public static EpdgTunnelManager getInstance(@NonNull Context context, int slotId) {
         return mTunnelManagerInstances.computeIfAbsent(
-                subId, k -> new EpdgTunnelManager(context, subId, new FeatureFlagsImpl()));
+                slotId, k -> new EpdgTunnelManager(context, slotId, new FeatureFlagsImpl()));
     }
 
     @VisibleForTesting
     public static void resetAllInstances() {
         mTunnelManagerInstances.clear();
+        sLastUnderlyingNetworkValidationMs = 0;
     }
 
     public interface TunnelCallback {
@@ -746,16 +814,24 @@ public class EpdgTunnelManager {
          *
          * @param apnName apn for which the tunnel was opened
          * @param linkProperties link properties of the tunnel
+         * @param onOpenedMetrics metrics for the tunnel
          */
-        void onOpened(@NonNull String apnName, @NonNull TunnelLinkProperties linkProperties);
+        void onOpened(
+                @NonNull String apnName,
+                @NonNull TunnelLinkProperties linkProperties,
+                OnOpenedMetrics onOpenedMetrics);
 
         /**
-         * Called when the tunnel is closed OR if bringup fails
+         * Called when the tunnel is closed OR if bring up fails
          *
          * @param apnName apn for which the tunnel was closed
          * @param error IwlanError carrying details of the error
+         * @param onClosedMetrics metrics for the tunnel
          */
-        void onClosed(@NonNull String apnName, @NonNull IwlanError error);
+        void onClosed(
+                @NonNull String apnName,
+                @NonNull IwlanError error,
+                OnClosedMetrics onClosedMetrics);
 
         /**
          * Called when updates upon network validation status change.
@@ -776,20 +852,17 @@ public class EpdgTunnelManager {
      * @param forceClose if {@code true}, triggers a local cleanup of the tunnel; if {@code false},
      *     performs a normal closure procedure
      * @param tunnelCallback The tunnelCallback for tunnel to be closed
-     * @param iwlanTunnelMetrics The metrics to be reported
      * @param reason The reason for tunnel to be closed
      */
     public void closeTunnel(
             @NonNull String apnName,
             boolean forceClose,
             @NonNull TunnelCallback tunnelCallback,
-            @NonNull IwlanTunnelMetricsImpl iwlanTunnelMetrics,
             @TunnelBringDownReason int reason) {
-        mHandler.sendMessage(
-                mHandler.obtainMessage(
+        mHandler.obtainMessage(
                         EVENT_TUNNEL_BRINGDOWN_REQUEST,
-                        new TunnelBringdownRequest(
-                                apnName, forceClose, tunnelCallback, iwlanTunnelMetrics, reason)));
+                        new TunnelBringdownRequest(apnName, forceClose, tunnelCallback, reason))
+                .sendToTarget();
     }
 
     /**
@@ -797,12 +870,12 @@ public class EpdgTunnelManager {
      * manager has state.
      *
      * @param network the network to be updated
-     * @param network the linkProperties to be updated
+     * @param linkProperties the linkProperties to be updated
      */
     public void updateNetwork(Network network, LinkProperties linkProperties) {
         UpdateNetworkWrapper updateNetworkWrapper =
                 new UpdateNetworkWrapper(network, linkProperties);
-        mHandler.sendMessage(mHandler.obtainMessage(EVENT_UPDATE_NETWORK, updateNetworkWrapper));
+        mHandler.obtainMessage(EVENT_UPDATE_NETWORK, updateNetworkWrapper).sendToTarget();
     }
 
     /**
@@ -815,9 +888,7 @@ public class EpdgTunnelManager {
      * @return true if params are valid and no existing tunnel. False otherwise.
      */
     public boolean bringUpTunnel(
-            @NonNull TunnelSetupRequest setupRequest,
-            @NonNull TunnelCallback tunnelCallback,
-            @NonNull TunnelMetricsInterface tunnelMetrics) {
+            @NonNull TunnelSetupRequest setupRequest, @NonNull TunnelCallback tunnelCallback) {
         String apnName = setupRequest.apnName();
 
         if (getTunnelSetupRequestApnName(setupRequest) == null) {
@@ -842,10 +913,9 @@ public class EpdgTunnelManager {
         }
 
         TunnelRequestWrapper tunnelRequestWrapper =
-                new TunnelRequestWrapper(setupRequest, tunnelCallback, tunnelMetrics);
+                new TunnelRequestWrapper(setupRequest, tunnelCallback);
 
-        mHandler.sendMessage(
-                mHandler.obtainMessage(EVENT_TUNNEL_BRINGUP_REQUEST, tunnelRequestWrapper));
+        mHandler.obtainMessage(EVENT_TUNNEL_BRINGUP_REQUEST, tunnelRequestWrapper).sendToTarget();
 
         return true;
     }
@@ -873,7 +943,6 @@ public class EpdgTunnelManager {
             TunnelRequestWrapper tunnelRequestWrapper, InetAddress epdgAddress) {
         TunnelSetupRequest setupRequest = tunnelRequestWrapper.getSetupRequest();
         TunnelCallback tunnelCallback = tunnelRequestWrapper.getTunnelCallback();
-        TunnelMetricsInterface tunnelMetrics = tunnelRequestWrapper.getTunnelMetrics();
         String apnName = setupRequest.apnName();
         IkeSessionParams ikeSessionParams;
         IpSecManager.IpSecTunnelInterface iface;
@@ -891,8 +960,8 @@ public class EpdgTunnelManager {
         if (Objects.isNull(ikeSessionParams)) {
             IwlanError iwlanError = new IwlanError(IwlanError.SIM_NOT_READY_EXCEPTION);
             reportIwlanError(apnName, iwlanError);
-            tunnelCallback.onClosed(apnName, iwlanError);
-            tunnelMetrics.onClosed(new OnClosedMetrics.Builder().setApnName(apnName).build());
+            tunnelCallback.onClosed(
+                    apnName, iwlanError, new OnClosedMetrics.Builder().setApnName(apnName).build());
             return;
         }
 
@@ -900,8 +969,8 @@ public class EpdgTunnelManager {
         if (Objects.isNull(iface)) {
             IwlanError iwlanError = new IwlanError(IwlanError.TUNNEL_TRANSFORM_FAILED);
             reportIwlanError(apnName, iwlanError);
-            tunnelCallback.onClosed(apnName, iwlanError);
-            tunnelMetrics.onClosed(new OnClosedMetrics.Builder().setApnName(apnName).build());
+            tunnelCallback.onClosed(
+                    apnName, iwlanError, new OnClosedMetrics.Builder().setApnName(apnName).build());
             return;
         }
 
@@ -921,7 +990,6 @@ public class EpdgTunnelManager {
                 apnName,
                 ikeSession,
                 tunnelCallback,
-                tunnelMetrics,
                 iface,
                 isSrcIpv6Present ? setupRequest.srcIpv6Address().get() : null,
                 setupRequest.srcIpv6AddressPrefixLength(),
@@ -1371,49 +1439,41 @@ public class EpdgTunnelManager {
                         mSlotId,
                         CarrierConfigManager.Iwlan.KEY_DIFFIE_HELLMAN_GROUPS_INT_ARRAY));
 
-        int[] encryptionAlgos =
+        String encryptionAlgosConfigKey =
                 isChildProposal
-                        ? IwlanCarrierConfig.getConfigIntArray(
-                                mContext,
-                                mSlotId,
-                                CarrierConfigManager.Iwlan
-                                    .KEY_SUPPORTED_CHILD_SESSION_ENCRYPTION_ALGORITHMS_INT_ARRAY)
-                        : IwlanCarrierConfig.getConfigIntArray(
-                                mContext,
-                                mSlotId,
-                                CarrierConfigManager.Iwlan
-                                    .KEY_SUPPORTED_IKE_SESSION_ENCRYPTION_ALGORITHMS_INT_ARRAY);
+                        ? CarrierConfigManager.Iwlan
+                                .KEY_SUPPORTED_CHILD_SESSION_ENCRYPTION_ALGORITHMS_INT_ARRAY
+                        : CarrierConfigManager.Iwlan
+                                .KEY_SUPPORTED_IKE_SESSION_ENCRYPTION_ALGORITHMS_INT_ARRAY;
+
+        int[] encryptionAlgos =
+                IwlanCarrierConfig.getConfigIntArray(mContext, mSlotId, encryptionAlgosConfigKey);
 
         for (int encryptionAlgo : encryptionAlgos) {
             if (encryptionAlgo == SaProposal.ENCRYPTION_ALGORITHM_AES_CBC) {
-                int[] aesCbcKeyLens =
+                String aesCbcKeyLensConfigKey =
                         isChildProposal
-                                ? IwlanCarrierConfig.getConfigIntArray(
-                                        mContext,
-                                        mSlotId,
-                                        CarrierConfigManager.Iwlan
-                                                .KEY_CHILD_SESSION_AES_CBC_KEY_SIZE_INT_ARRAY)
-                                : IwlanCarrierConfig.getConfigIntArray(
-                                        mContext,
-                                        mSlotId,
-                                        CarrierConfigManager.Iwlan
-                                                .KEY_IKE_SESSION_AES_CBC_KEY_SIZE_INT_ARRAY);
+                                ? CarrierConfigManager.Iwlan
+                                        .KEY_CHILD_SESSION_AES_CBC_KEY_SIZE_INT_ARRAY
+                                : CarrierConfigManager.Iwlan
+                                        .KEY_IKE_SESSION_AES_CBC_KEY_SIZE_INT_ARRAY;
+
+                int[] aesCbcKeyLens =
+                        IwlanCarrierConfig.getConfigIntArray(
+                                mContext, mSlotId, aesCbcKeyLensConfigKey);
                 epdgSaProposal.addProposedEncryptionAlgorithm(encryptionAlgo, aesCbcKeyLens);
             }
 
             if (encryptionAlgo == SaProposal.ENCRYPTION_ALGORITHM_AES_CTR) {
-                int[] aesCtrKeyLens =
+                String aesCtrKeyLensConfigKey =
                         isChildProposal
-                                ? IwlanCarrierConfig.getConfigIntArray(
-                                        mContext,
-                                        mSlotId,
-                                        CarrierConfigManager.Iwlan
-                                                .KEY_CHILD_SESSION_AES_CTR_KEY_SIZE_INT_ARRAY)
-                                : IwlanCarrierConfig.getConfigIntArray(
-                                        mContext,
-                                        mSlotId,
-                                        CarrierConfigManager.Iwlan
-                                                .KEY_IKE_SESSION_AES_CTR_KEY_SIZE_INT_ARRAY);
+                                ? CarrierConfigManager.Iwlan
+                                        .KEY_CHILD_SESSION_AES_CTR_KEY_SIZE_INT_ARRAY
+                                : CarrierConfigManager.Iwlan
+                                        .KEY_IKE_SESSION_AES_CTR_KEY_SIZE_INT_ARRAY;
+                int[] aesCtrKeyLens =
+                        IwlanCarrierConfig.getConfigIntArray(
+                                mContext, mSlotId, aesCtrKeyLensConfigKey);
                 epdgSaProposal.addProposedEncryptionAlgorithm(encryptionAlgo, aesCtrKeyLens);
             }
         }
@@ -1427,18 +1487,14 @@ public class EpdgTunnelManager {
                                     .KEY_SUPPORTED_INTEGRITY_ALGORITHMS_INT_ARRAY));
         }
 
-        int[] aeadAlgos =
+        String aeadAlgosConfigKey =
                 isChildProposal
-                        ? IwlanCarrierConfig.getConfigIntArray(
-                                mContext,
-                                mSlotId,
-                                CarrierConfigManager.Iwlan
-                                        .KEY_SUPPORTED_CHILD_SESSION_AEAD_ALGORITHMS_INT_ARRAY)
-                        : IwlanCarrierConfig.getConfigIntArray(
-                                mContext,
-                                mSlotId,
-                                CarrierConfigManager.Iwlan
-                                        .KEY_SUPPORTED_IKE_SESSION_AEAD_ALGORITHMS_INT_ARRAY);
+                        ? CarrierConfigManager.Iwlan
+                                .KEY_SUPPORTED_CHILD_SESSION_AEAD_ALGORITHMS_INT_ARRAY
+                        : CarrierConfigManager.Iwlan
+                                .KEY_SUPPORTED_IKE_SESSION_AEAD_ALGORITHMS_INT_ARRAY;
+        int[] aeadAlgos =
+                IwlanCarrierConfig.getConfigIntArray(mContext, mSlotId, aeadAlgosConfigKey);
         for (int aeadAlgo : aeadAlgos) {
             if (!validateConfig(aeadAlgo, VALID_AEAD_ALGOS, CONFIG_TYPE_ENCRYPT_ALGO)) {
                 continue;
@@ -1446,18 +1502,15 @@ public class EpdgTunnelManager {
             if ((aeadAlgo == SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_8)
                     || (aeadAlgo == SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_12)
                     || (aeadAlgo == SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_16)) {
-                int[] aesGcmKeyLens =
+                String aesGcmKeyLensConfigKey =
                         isChildProposal
-                                ? IwlanCarrierConfig.getConfigIntArray(
-                                        mContext,
-                                        mSlotId,
-                                        CarrierConfigManager.Iwlan
-                                                .KEY_CHILD_SESSION_AES_GCM_KEY_SIZE_INT_ARRAY)
-                                : IwlanCarrierConfig.getConfigIntArray(
-                                        mContext,
-                                        mSlotId,
-                                        CarrierConfigManager.Iwlan
-                                                .KEY_IKE_SESSION_AES_GCM_KEY_SIZE_INT_ARRAY);
+                                ? CarrierConfigManager.Iwlan
+                                        .KEY_CHILD_SESSION_AES_GCM_KEY_SIZE_INT_ARRAY
+                                : CarrierConfigManager.Iwlan
+                                        .KEY_IKE_SESSION_AES_GCM_KEY_SIZE_INT_ARRAY;
+                int[] aesGcmKeyLens =
+                        IwlanCarrierConfig.getConfigIntArray(
+                                mContext, mSlotId, aesGcmKeyLensConfigKey);
                 epdgSaProposal.addProposedAeadAlgorithm(aeadAlgo, aesGcmKeyLens);
             }
         }
@@ -1776,16 +1829,14 @@ public class EpdgTunnelManager {
                         ? CarrierConfigManager.Iwlan.KEY_IKE_LOCAL_ID_TYPE_INT
                         : CarrierConfigManager.Iwlan.KEY_IKE_REMOTE_ID_TYPE_INT;
         int idType = IwlanCarrierConfig.getConfigInt(mContext, mSlotId, idTypeConfig);
-        switch (idType) {
-            case CarrierConfigManager.Iwlan.ID_TYPE_FQDN:
-                return new IkeFqdnIdentification(id);
-            case CarrierConfigManager.Iwlan.ID_TYPE_KEY_ID:
-                return new IkeKeyIdIdentification(id.getBytes(StandardCharsets.US_ASCII));
-            case CarrierConfigManager.Iwlan.ID_TYPE_RFC822_ADDR:
-                return new IkeRfc822AddrIdentification(id);
-            default:
-                throw new IllegalArgumentException("Invalid local Identity type: " + idType);
-        }
+        return switch (idType) {
+            case CarrierConfigManager.Iwlan.ID_TYPE_FQDN -> new IkeFqdnIdentification(id);
+            case CarrierConfigManager.Iwlan.ID_TYPE_KEY_ID ->
+                    new IkeKeyIdIdentification(id.getBytes(StandardCharsets.US_ASCII));
+            case CarrierConfigManager.Iwlan.ID_TYPE_RFC822_ADDR ->
+                    new IkeRfc822AddrIdentification(id);
+            default -> throw new IllegalArgumentException("Invalid local Identity type: " + idType);
+        };
     }
 
     private EapSessionConfig getEapConfig() throws IwlanSimNotReadyException {
@@ -1820,9 +1871,8 @@ public class EpdgTunnelManager {
                         + sessionType);
         exception.printStackTrace();
 
-        mHandler.sendMessage(
-                mHandler.obtainMessage(
-                        sessionType, new SessionClosedData(apnName, token, exception)));
+        mHandler.obtainMessage(sessionType, new SessionClosedData(apnName, token, exception))
+                .sendToTarget();
     }
 
     private boolean isEpdgSelectionOrFirstTunnelBringUpInProgress() {
@@ -1857,7 +1907,6 @@ public class EpdgTunnelManager {
             OnClosedMetrics.Builder onClosedMetricsBuilder;
             TunnelRequestWrapper tunnelRequestWrapper;
             ConnectivityManager connectivityManager;
-            NetworkCapabilities networkCapabilities;
             boolean isNetworkValidated;
             switch (msg.what) {
                 case EVENT_CHILD_SESSION_OPENED:
@@ -1944,33 +1993,27 @@ public class EpdgTunnelManager {
                                     .setIfaceName(tunnelConfig.getIface().getInterfaceName())
                                     .setSliceInfo(tunnelConfig.getSliceInfo())
                                     .build();
-                    tunnelConfig.getTunnelCallback().onOpened(apnName, linkProperties);
-
-                    reportIwlanError(apnName, new IwlanError(IwlanError.NO_ERROR));
-                    getEpdgSelector().onEpdgConnectedSuccessfully();
 
                     mIkeTunnelEstablishmentDuration =
                             System.currentTimeMillis() - mIkeTunnelEstablishmentStartTime;
                     mIkeTunnelEstablishmentStartTime = 0;
-                    connectivityManager = mContext.getSystemService(ConnectivityManager.class);
-                    networkCapabilities =
-                            connectivityManager.getNetworkCapabilities(mIkeSessionNetwork);
-                    isNetworkValidated =
-                            (networkCapabilities != null)
-                                    && networkCapabilities.hasCapability(
-                                            NetworkCapabilities.NET_CAPABILITY_VALIDATED);
+                    isNetworkValidated = isUnderlyingNetworkValidated(mIkeSessionNetwork);
+                    OnOpenedMetrics onOpenedMetrics =
+                            new OnOpenedMetrics.Builder()
+                                    .setApnName(apnName)
+                                    .setEpdgServerAddress(tunnelConfig.getEpdgAddress())
+                                    .setEpdgServerSelectionDuration(
+                                            (int) mEpdgServerSelectionDuration)
+                                    .setIkeTunnelEstablishmentDuration(
+                                            (int) mIkeTunnelEstablishmentDuration)
+                                    .setIsNetworkValidated(isNetworkValidated)
+                                    .build();
                     tunnelConfig
-                            .getTunnelMetrics()
-                            .onOpened(
-                                    new OnOpenedMetrics.Builder()
-                                            .setApnName(apnName)
-                                            .setEpdgServerAddress(tunnelConfig.getEpdgAddress())
-                                            .setEpdgServerSelectionDuration(
-                                                    (int) mEpdgServerSelectionDuration)
-                                            .setIkeTunnelEstablishmentDuration(
-                                                    (int) mIkeTunnelEstablishmentDuration)
-                                            .setIsNetworkValidated(isNetworkValidated)
-                                            .build());
+                            .getTunnelCallback()
+                            .onOpened(apnName, linkProperties, onOpenedMetrics);
+
+                    reportIwlanError(apnName, new IwlanError(IwlanError.NO_ERROR));
+                    mEpdgSelector.onEpdgConnectedSuccessfully();
 
                     mEpdgMonitor.onApnConnectToEpdg(apnName, tunnelConfig.getEpdgAddress());
                     onConnectedToEpdg(true);
@@ -2008,8 +2051,9 @@ public class EpdgTunnelManager {
                         // Iwlan reports IKE_SESSION_CLOSED_BEFORE_CHILD_SESSION_OPENED
                         // instead of NO_ERROR
                         if (!tunnelConfig.hasTunnelOpened()) {
-                            iwlanError = new IwlanError(
-                                    IwlanError.IKE_SESSION_CLOSED_BEFORE_CHILD_SESSION_OPENED);
+                            int errorType =
+                                    IwlanError.IKE_SESSION_CLOSED_BEFORE_CHILD_SESSION_OPENED;
+                            iwlanError = new IwlanError(errorType);
                         } else {
                             iwlanError = tunnelConfig.getError();
                         }
@@ -2028,17 +2072,21 @@ public class EpdgTunnelManager {
                         }
                         mEpdgMonitor.onEpdgConnectionFailed(
                                 tunnelConfig.isEmergency(), tunnelConfig.getEpdgAddress());
-                        getEpdgSelector().onEpdgConnectionFailed(tunnelConfig.getEpdgAddress());
+                        if (sessionClosedData.mIkeException != null) {
+                            mEpdgSelector.onEpdgConnectionFailed(
+                                    tunnelConfig.getEpdgAddress(), sessionClosedData.mIkeException);
+                        }
+                    } else {
+                        /* PDN disconnected case */
+                        triggerUnderlyingNetworkValidationOnError(iwlanError);
                     }
 
                     Log.d(TAG, "Tunnel Closed: " + iwlanError);
                     tunnelConfig.setIkeSessionState(IkeSessionState.NO_IKE_SESSION);
-                    tunnelConfig.getTunnelCallback().onClosed(apnName, iwlanError);
-                    onClosedMetricsBuilder = new OnClosedMetrics.Builder().setApnName(apnName);
 
+                    onClosedMetricsBuilder = new OnClosedMetrics.Builder().setApnName(apnName);
                     if (!mEpdgMonitor.hasEpdgConnected()) {
                         failAllPendingRequests(iwlanError);
-                        tunnelConfig.getTunnelMetrics().onClosed(onClosedMetricsBuilder.build());
                     } else {
                         mIkeTunnelEstablishmentDuration =
                                 mIkeTunnelEstablishmentStartTime > 0
@@ -2047,21 +2095,17 @@ public class EpdgTunnelManager {
                                         : 0;
                         mIkeTunnelEstablishmentStartTime = 0;
 
-                        connectivityManager = mContext.getSystemService(ConnectivityManager.class);
-                        networkCapabilities =
-                                connectivityManager.getNetworkCapabilities(mIkeSessionNetwork);
-                        isNetworkValidated =
-                                (networkCapabilities != null)
-                                        && networkCapabilities.hasCapability(
-                                                NetworkCapabilities.NET_CAPABILITY_VALIDATED);
+                        isNetworkValidated = isUnderlyingNetworkValidated(mIkeSessionNetwork);
                         onClosedMetricsBuilder
                                 .setEpdgServerAddress(tunnelConfig.getEpdgAddress())
                                 .setEpdgServerSelectionDuration((int) mEpdgServerSelectionDuration)
                                 .setIkeTunnelEstablishmentDuration(
                                         (int) mIkeTunnelEstablishmentDuration)
                                 .setIsNetworkValidated(isNetworkValidated);
-                        tunnelConfig.getTunnelMetrics().onClosed(onClosedMetricsBuilder.build());
                     }
+                    tunnelConfig
+                            .getTunnelCallback()
+                            .onClosed(apnName, iwlanError, onClosedMetricsBuilder.build());
 
                     mApnNameToTunnelConfig.remove(apnName);
                     mEpdgMonitor.onApnDisconnectFromEpdg(apnName);
@@ -2158,8 +2202,9 @@ public class EpdgTunnelManager {
                         // found. Recovers state in IwlanDataService through TunnelCallback.
                         iwlanError = new IwlanError(IwlanError.TUNNEL_NOT_FOUND);
                         reportIwlanError(apnName, iwlanError);
-                        bringdownRequest.mTunnelCallback.onClosed(apnName, iwlanError);
-                        bringdownRequest.mIwlanTunnelMetrics.onClosed(
+                        bringdownRequest.mTunnelCallback.onClosed(
+                                apnName,
+                                iwlanError,
                                 new OnClosedMetrics.Builder().setApnName(apnName).build());
                     }
                     break;
@@ -2233,8 +2278,8 @@ public class EpdgTunnelManager {
 
                     if (enabledFastReauth) {
                         EapInfo eapInfo = sessionConfiguration.getEapInfo();
-                        if (eapInfo instanceof EapAkaInfo) {
-                            mNextReauthId = ((EapAkaInfo) eapInfo).getReauthId();
+                        if (eapInfo instanceof EapAkaInfo eapAkaInfo) {
+                            mNextReauthId = eapAkaInfo.getReauthId();
                             Log.d(TAG, "Update ReauthId: " + Arrays.toString(mNextReauthId));
                         } else {
                             mNextReauthId = null;
@@ -2335,13 +2380,15 @@ public class EpdgTunnelManager {
         private void handleTunnelBringUpRequest(TunnelRequestWrapper tunnelRequestWrapper) {
             TunnelSetupRequest setupRequest = tunnelRequestWrapper.getSetupRequest();
             String apnName = setupRequest.apnName();
-            OnClosedMetrics.Builder onClosedMetricsBuilder =
-                    new OnClosedMetrics.Builder().setApnName(apnName);
 
             IwlanError bringUpError = canBringUpTunnel(apnName, setupRequest.isEmergency());
             if (Objects.nonNull(bringUpError)) {
-                tunnelRequestWrapper.getTunnelCallback().onClosed(apnName, bringUpError);
-                tunnelRequestWrapper.getTunnelMetrics().onClosed(onClosedMetricsBuilder.build());
+                tunnelRequestWrapper
+                        .getTunnelCallback()
+                        .onClosed(
+                                apnName,
+                                bringUpError,
+                                new OnClosedMetrics.Builder().setApnName(apnName).build());
                 return;
             }
             serviceTunnelBringUpRequest(tunnelRequestWrapper);
@@ -2444,9 +2491,8 @@ public class EpdgTunnelManager {
                 Log.w(TAG, "Invalid Ip preference : " + ipPreference);
         }
 
-        EpdgSelector epdgSelector = getEpdgSelector();
         IwlanError epdgError =
-                epdgSelector.getValidatedServerList(
+                mEpdgSelector.getValidatedServerList(
                         mTransactionId,
                         protoFilter,
                         epdgAddressOrder,
@@ -2461,11 +2507,6 @@ public class EpdgTunnelManager {
         }
     }
 
-    @VisibleForTesting
-    EpdgSelector getEpdgSelector() {
-        return EpdgSelector.getSelectorInstance(mContext, mSlotId);
-    }
-
     @VisibleForTesting
     int closePendingRequestsForApn(String apnName) {
         int numRequestsClosed = 0;
@@ -2479,10 +2520,9 @@ public class EpdgTunnelManager {
             if (requestWrapper.getSetupRequest().apnName().equals(apnName)) {
                 requestWrapper
                         .getTunnelCallback()
-                        .onClosed(apnName, new IwlanError(IwlanError.NO_ERROR));
-                requestWrapper
-                        .getTunnelMetrics()
                         .onClosed(
+                                apnName,
+                                new IwlanError(IwlanError.NO_ERROR),
                                 new OnClosedMetrics.Builder()
                                         .setApnName(apnName)
                                         .setEpdgServerAddress(null)
@@ -2560,9 +2600,10 @@ public class EpdgTunnelManager {
             TunnelSetupRequest setupRequest = request.getSetupRequest();
             String apnName = setupRequest.apnName();
             reportIwlanError(apnName, error);
-            request.getTunnelCallback().onClosed(apnName, error);
-            request.getTunnelMetrics()
+            request.getTunnelCallback()
                     .onClosed(
+                            apnName,
+                            error,
                             new OnClosedMetrics.Builder()
                                     .setApnName(apnName)
                                     .setEpdgServerAddress(null)
@@ -2601,15 +2642,11 @@ public class EpdgTunnelManager {
     private static final class TunnelRequestWrapper {
         private final TunnelSetupRequest mSetupRequest;
         private final TunnelCallback mTunnelCallback;
-        private final TunnelMetricsInterface mTunnelMetrics;
 
         private TunnelRequestWrapper(
-                TunnelSetupRequest setupRequest,
-                TunnelCallback tunnelCallback,
-                TunnelMetricsInterface tunnelMetrics) {
+                TunnelSetupRequest setupRequest, TunnelCallback tunnelCallback) {
             mTunnelCallback = tunnelCallback;
             mSetupRequest = setupRequest;
-            mTunnelMetrics = tunnelMetrics;
         }
 
         public TunnelSetupRequest getSetupRequest() {
@@ -2619,29 +2656,22 @@ public class EpdgTunnelManager {
         public TunnelCallback getTunnelCallback() {
             return mTunnelCallback;
         }
-
-        public TunnelMetricsInterface getTunnelMetrics() {
-            return mTunnelMetrics;
-        }
     }
 
     private static final class TunnelBringdownRequest {
         final String mApnName;
         final boolean mForceClose;
         final TunnelCallback mTunnelCallback;
-        final IwlanTunnelMetricsImpl mIwlanTunnelMetrics;
         final int mBringDownReason;
 
         private TunnelBringdownRequest(
                 String apnName,
                 boolean forceClose,
                 TunnelCallback tunnelCallback,
-                IwlanTunnelMetricsImpl iwlanTunnelMetrics,
                 @TunnelBringDownReason int reason) {
             mApnName = apnName;
             mForceClose = forceClose;
             mTunnelCallback = tunnelCallback;
-            mIwlanTunnelMetrics = iwlanTunnelMetrics;
             mBringDownReason = reason;
         }
     }
@@ -2905,7 +2935,6 @@ public class EpdgTunnelManager {
             String apnName,
             IkeSession ikeSession,
             TunnelCallback tunnelCallback,
-            TunnelMetricsInterface tunnelMetrics,
             IpSecManager.IpSecTunnelInterface iface,
             InetAddress srcIpv6Addr,
             int srcIPv6AddrPrefixLen,
@@ -2916,7 +2945,6 @@ public class EpdgTunnelManager {
                 new TunnelConfig(
                         ikeSession,
                         tunnelCallback,
-                        tunnelMetrics,
                         iface,
                         srcIpv6Addr,
                         srcIPv6AddrPrefixLen,
@@ -2956,9 +2984,8 @@ public class EpdgTunnelManager {
         mEpdgServerSelectionStartTime = 0;
         EpdgSelectorResult epdgSelectorResult =
                 new EpdgSelectorResult(validIPList, result, transactionId);
-        mHandler.sendMessage(
-                mHandler.obtainMessage(
-                        EVENT_EPDG_ADDRESS_SELECTION_REQUEST_COMPLETE, epdgSelectorResult));
+        mHandler.obtainMessage(EVENT_EPDG_ADDRESS_SELECTION_REQUEST_COMPLETE, epdgSelectorResult)
+                .sendToTarget();
     }
 
     static boolean isValidApnProtocol(int proto) {
@@ -2975,38 +3002,25 @@ public class EpdgTunnelManager {
     }
 
     private static String eventToString(int event) {
-        switch (event) {
-            case EVENT_TUNNEL_BRINGUP_REQUEST:
-                return "EVENT_TUNNEL_BRINGUP_REQUEST";
-            case EVENT_TUNNEL_BRINGDOWN_REQUEST:
-                return "EVENT_TUNNEL_BRINGDOWN_REQUEST";
-            case EVENT_CHILD_SESSION_OPENED:
-                return "EVENT_CHILD_SESSION_OPENED";
-            case EVENT_CHILD_SESSION_CLOSED:
-                return "EVENT_CHILD_SESSION_CLOSED";
-            case EVENT_IKE_SESSION_CLOSED:
-                return "EVENT_IKE_SESSION_CLOSED";
-            case EVENT_EPDG_ADDRESS_SELECTION_REQUEST_COMPLETE:
-                return "EVENT_EPDG_ADDRESS_SELECTION_REQUEST_COMPLETE";
-            case EVENT_IPSEC_TRANSFORM_CREATED:
-                return "EVENT_IPSEC_TRANSFORM_CREATED";
-            case EVENT_IPSEC_TRANSFORM_DELETED:
-                return "EVENT_IPSEC_TRANSFORM_DELETED";
-            case EVENT_UPDATE_NETWORK:
-                return "EVENT_UPDATE_NETWORK";
-            case EVENT_IKE_SESSION_OPENED:
-                return "EVENT_IKE_SESSION_OPENED";
-            case EVENT_IKE_SESSION_CONNECTION_INFO_CHANGED:
-                return "EVENT_IKE_SESSION_CONNECTION_INFO_CHANGED";
-            case EVENT_IKE_3GPP_DATA_RECEIVED:
-                return "EVENT_IKE_3GPP_DATA_RECEIVED";
-            case EVENT_IKE_LIVENESS_STATUS_CHANGED:
-                return "EVENT_IKE_LIVENESS_STATUS_CHANGED";
-            case EVENT_REQUEST_NETWORK_VALIDATION_CHECK:
-                return "EVENT_REQUEST_NETWORK_VALIDATION_CHECK";
-            default:
-                return "Unknown(" + event + ")";
-        }
+        return switch (event) {
+            case EVENT_TUNNEL_BRINGUP_REQUEST -> "EVENT_TUNNEL_BRINGUP_REQUEST";
+            case EVENT_TUNNEL_BRINGDOWN_REQUEST -> "EVENT_TUNNEL_BRINGDOWN_REQUEST";
+            case EVENT_CHILD_SESSION_OPENED -> "EVENT_CHILD_SESSION_OPENED";
+            case EVENT_CHILD_SESSION_CLOSED -> "EVENT_CHILD_SESSION_CLOSED";
+            case EVENT_IKE_SESSION_CLOSED -> "EVENT_IKE_SESSION_CLOSED";
+            case EVENT_EPDG_ADDRESS_SELECTION_REQUEST_COMPLETE ->
+                    "EVENT_EPDG_ADDRESS_SELECTION_REQUEST_COMPLETE";
+            case EVENT_IPSEC_TRANSFORM_CREATED -> "EVENT_IPSEC_TRANSFORM_CREATED";
+            case EVENT_IPSEC_TRANSFORM_DELETED -> "EVENT_IPSEC_TRANSFORM_DELETED";
+            case EVENT_UPDATE_NETWORK -> "EVENT_UPDATE_NETWORK";
+            case EVENT_IKE_SESSION_OPENED -> "EVENT_IKE_SESSION_OPENED";
+            case EVENT_IKE_SESSION_CONNECTION_INFO_CHANGED ->
+                    "EVENT_IKE_SESSION_CONNECTION_INFO_CHANGED";
+            case EVENT_IKE_3GPP_DATA_RECEIVED -> "EVENT_IKE_3GPP_DATA_RECEIVED";
+            case EVENT_IKE_LIVENESS_STATUS_CHANGED -> "EVENT_IKE_LIVENESS_STATUS_CHANGED";
+            case EVENT_REQUEST_NETWORK_VALIDATION_CHECK -> "EVENT_REQUEST_NETWORK_VALIDATION_CHECK";
+            default -> "Unknown(" + event + ")";
+        };
     }
 
     @VisibleForTesting
@@ -3039,11 +3053,13 @@ public class EpdgTunnelManager {
 
     @VisibleForTesting
     long reportIwlanError(String apnName, IwlanError error) {
+        triggerUnderlyingNetworkValidationOnError(error);
         return ErrorPolicyManager.getInstance(mContext, mSlotId).reportIwlanError(apnName, error);
     }
 
     @VisibleForTesting
     long reportIwlanError(String apnName, IwlanError error, long backOffTime) {
+        triggerUnderlyingNetworkValidationOnError(error);
         return ErrorPolicyManager.getInstance(mContext, mSlotId)
                 .reportIwlanError(apnName, error, backOffTime);
     }
@@ -3108,6 +3124,130 @@ public class EpdgTunnelManager {
         return new IpPreferenceConflict();
     }
 
+    private boolean isUnderlyingNetworkValidated(Network network) {
+        ConnectivityManager connectivityManager =
+                Objects.requireNonNull(mContext).getSystemService(ConnectivityManager.class);
+        NetworkCapabilities networkCapabilities =
+                connectivityManager.getNetworkCapabilities(network);
+        return (networkCapabilities != null)
+                && networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED);
+    }
+
+    /**
+     * Trigger network validation on the underlying network if needed to possibly update validation
+     * status and cause system switch default network.
+     */
+    void triggerUnderlyingNetworkValidationOnError(IwlanError error) {
+        if (!isUnderlyingNetworkValidationRequired(error.getErrorType())) {
+            return;
+        }
+
+        Log.d(TAG, "On triggering underlying network validation. Cause: " + error);
+        validateUnderlyingNetwork(IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_NO_RESPONSE);
+    }
+
+    public void validateUnderlyingNetwork(@IwlanCarrierConfig.NetworkValidationEvent int event) {
+        int[] networkValidationEvents =
+                IwlanCarrierConfig.getConfigIntArray(
+                        mContext,
+                        mSlotId,
+                        IwlanCarrierConfig.KEY_UNDERLYING_NETWORK_VALIDATION_EVENTS_INT_ARRAY);
+        if (Arrays.stream(networkValidationEvents)
+                .noneMatch(validationEvent -> validationEvent == event)) {
+            return;
+        }
+        synchronized (sLastUnderlyingNetworkValidationLock) {
+            long now = IwlanHelper.elapsedRealtime();
+            // TODO (b/356791418): Consolidate underlying network handling into a single centralized
+            //  subcomponent to prevent duplicate processing across different threads and classes
+            //  . Until then, we will prevent sending duplicate network validations by checking
+            //  the recent trigger time.
+            if (now - sLastUnderlyingNetworkValidationMs > NETWORK_VALIDATION_MIN_INTERVAL_MS) {
+                sLastUnderlyingNetworkValidationMs = now;
+                Log.d(
+                        TAG,
+                        "On triggering underlying network validation. Event: "
+                                + IwlanCarrierConfig.getUnderlyingNetworkValidationEventString(
+                                        event));
+                mHandler.post(() -> onTriggerUnderlyingNetworkValidation(event));
+            }
+        }
+    }
+
+    private void onTriggerUnderlyingNetworkValidation(int event) {
+        if (!isUnderlyingNetworkValidated(mDefaultNetwork)) {
+            Log.d(TAG, "Network " + mDefaultNetwork + " is already not validated.");
+            return;
+        }
+
+        setupValidationMetricsAtom(event);
+        ConnectivityManager connectivityManager =
+                Objects.requireNonNull(mContext).getSystemService(ConnectivityManager.class);
+        Log.d(TAG, "Trigger underlying network validation on network: " + mDefaultNetwork);
+        connectivityManager.reportNetworkConnectivity(mDefaultNetwork, false);
+    }
+
+    private void setupValidationMetricsAtom(int event) {
+        MetricsAtom metricsAtom = new MetricsAtom();
+        metricsAtom.setMessageId(IwlanStatsLog.IWLAN_UNDERLYING_NETWORK_VALIDATION_RESULT_REPORTED);
+        metricsAtom.setTriggerReason(getMetricsTriggerReason(event));
+
+        ConnectivityManager connectivityManager =
+                Objects.requireNonNull(mContext).getSystemService(ConnectivityManager.class);
+        NetworkCapabilities networkCapabilities =
+                Objects.requireNonNull(connectivityManager).getNetworkCapabilities(mDefaultNetwork);
+        int validationTransportType = NETWORK_VALIDATION_TRANSPORT_TYPE_UNSPECIFIED;
+        if (networkCapabilities != null) {
+            if (networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
+                validationTransportType = NETWORK_VALIDATION_TRANSPORT_TYPE_CELLULAR;
+            } else if (networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
+                validationTransportType = NETWORK_VALIDATION_TRANSPORT_TYPE_WIFI;
+            }
+        }
+        metricsAtom.setValidationTransportType(validationTransportType);
+
+        metricsAtom.setValidationStartTimeMills(IwlanHelper.elapsedRealtime());
+        mMetricsAtomForNetwork.put(mDefaultNetwork, metricsAtom);
+    }
+
+    boolean isUnderlyingNetworkValidationRequired(int error) {
+        return switch (error) {
+            case IwlanError.EPDG_SELECTOR_SERVER_SELECTION_FAILED,
+                            IwlanError.IKE_NETWORK_LOST_EXCEPTION,
+                            IwlanError.IKE_INIT_TIMEOUT,
+                            IwlanError.IKE_MOBILITY_TIMEOUT,
+                            IwlanError.IKE_DPD_TIMEOUT ->
+                    true;
+            default -> false;
+        };
+    }
+
+    private int getMetricsValidationResult(int validationResult) {
+        return switch (validationResult) {
+            case ConnectivityReport.NETWORK_VALIDATION_RESULT_INVALID ->
+                    NETWORK_VALIDATION_RESULT_INVALID;
+            case ConnectivityReport.NETWORK_VALIDATION_RESULT_VALID ->
+                    NETWORK_VALIDATION_RESULT_VALID;
+            case ConnectivityReport.NETWORK_VALIDATION_RESULT_PARTIALLY_VALID ->
+                    NETWORK_VALIDATION_RESULT_PARTIALLY_VALID;
+            case ConnectivityReport.NETWORK_VALIDATION_RESULT_SKIPPED ->
+                    NETWORK_VALIDATION_RESULT_SKIPPED;
+            default -> NETWORK_VALIDATION_RESULT_UNSPECIFIED;
+        };
+    }
+
+    private int getMetricsTriggerReason(int reason) {
+        return switch (reason) {
+            case IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_MAKING_CALL ->
+                    NETWORK_VALIDATION_EVENT_MAKING_CALL;
+            case IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_SCREEN_ON ->
+                    NETWORK_VALIDATION_EVENT_SCREEN_ON;
+            case IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_NO_RESPONSE ->
+                    NETWORK_VALIDATION_EVENT_NO_RESPONSE;
+            default -> NETWORK_VALIDATION_EVENT_UNSPECIFIED;
+        };
+    }
+
     /**
      * Performs network validation check
      *
@@ -3122,6 +3262,30 @@ public class EpdgTunnelManager {
         mApnNameToTunnelConfig.remove(apnName);
     }
 
+    public void prefetchEpdgServerList(Network network, boolean isRoaming) {
+        mEpdgSelector.getValidatedServerList(
+                0 /* transactionId */,
+                EpdgSelector.PROTO_FILTER_IPV4V6,
+                EpdgSelector.SYSTEM_PREFERRED,
+                isRoaming,
+                false /* isEmergency */,
+                network,
+                null /* selectorCallback */);
+        mEpdgSelector.getValidatedServerList(
+                0 /* transactionId */,
+                EpdgSelector.PROTO_FILTER_IPV4V6,
+                EpdgSelector.SYSTEM_PREFERRED,
+                isRoaming,
+                true /* isEmergency */,
+                network,
+                null /* selectorCallback */);
+    }
+
+    public void close() {
+        mTunnelManagerInstances.remove(mSlotId);
+        unregisterConnectivityDiagnosticsCallback();
+    }
+
     public void dump(PrintWriter pw) {
         pw.println("---- EpdgTunnelManager ----");
         pw.println(
diff --git a/src/com/google/android/iwlan/epdg/NaptrDnsResolver.java b/src/com/google/android/iwlan/epdg/NaptrDnsResolver.java
index 701afd5..0b46532 100644
--- a/src/com/google/android/iwlan/epdg/NaptrDnsResolver.java
+++ b/src/com/google/android/iwlan/epdg/NaptrDnsResolver.java
@@ -121,16 +121,11 @@ final class NaptrDnsResolver {
 
             @NaptrRecordType
             public int getTypeFromFlagString() {
-                switch (flag) {
-                    case "S":
-                    case "s":
-                        return TYPE_SRV;
-                    case "A":
-                    case "a":
-                        return TYPE_A;
-                    default:
-                        throw new ParseException("Unsupported flag type: " + flag);
-                }
+                return switch (flag) {
+                    case "S", "s" -> TYPE_SRV;
+                    case "A", "a" -> TYPE_A;
+                    default -> throw new ParseException("Unsupported flag type: " + flag);
+                };
             }
 
             NaptrRecord(byte[] naptrRecordData) throws ParseException {
diff --git a/src/com/google/android/iwlan/epdg/NetworkSliceSelectionAssistanceInformation.java b/src/com/google/android/iwlan/epdg/NetworkSliceSelectionAssistanceInformation.java
index 669aa5d..761517e 100644
--- a/src/com/google/android/iwlan/epdg/NetworkSliceSelectionAssistanceInformation.java
+++ b/src/com/google/android/iwlan/epdg/NetworkSliceSelectionAssistanceInformation.java
@@ -16,7 +16,7 @@ public class NetworkSliceSelectionAssistanceInformation {
         if (snssai == null) {
             return null;
         }
-        /**
+        /*
          * From 3GPP TS 24.501 Section 9.11.2.8, Content structure of the Value of S-NSSAI
          *
          * <p>Slice Service Type - 1 byte
@@ -75,7 +75,7 @@ public class NetworkSliceSelectionAssistanceInformation {
         if (offset < 0 || snssai.length < offset + 1) {
             return NetworkSliceInfo.SLICE_SERVICE_TYPE_NONE;
         }
-        /**
+        /*
          * From 3GPP TS 23.003: Values 0 to 127 belong to the standardized SST range and they are
          * defined in 3GPP TS 23.501. Values 128 to 255 belong to the Operator-specific range
          */
diff --git a/src/com/google/android/iwlan/proto/MetricsAtom.java b/src/com/google/android/iwlan/proto/MetricsAtom.java
index 0fe4d0f..8e17516 100644
--- a/src/com/google/android/iwlan/proto/MetricsAtom.java
+++ b/src/com/google/android/iwlan/proto/MetricsAtom.java
@@ -27,6 +27,21 @@ public class MetricsAtom {
     public static int INVALID_MESSAGE_ID = -1;
     private static final String TAG = "IwlanMetrics";
 
+    public static final int NETWORK_VALIDATION_TRANSPORT_TYPE_UNSPECIFIED = 0;
+    public static final int NETWORK_VALIDATION_TRANSPORT_TYPE_CELLULAR = 1;
+    public static final int NETWORK_VALIDATION_TRANSPORT_TYPE_WIFI = 2;
+
+    public static final int NETWORK_VALIDATION_EVENT_UNSPECIFIED = 0;
+    public static final int NETWORK_VALIDATION_EVENT_MAKING_CALL = 1;
+    public static final int NETWORK_VALIDATION_EVENT_SCREEN_ON = 2;
+    public static final int NETWORK_VALIDATION_EVENT_NO_RESPONSE = 3;
+
+    public static final int NETWORK_VALIDATION_RESULT_UNSPECIFIED = 0;
+    public static final int NETWORK_VALIDATION_RESULT_INVALID = 1;
+    public static final int NETWORK_VALIDATION_RESULT_VALID = 2;
+    public static final int NETWORK_VALIDATION_RESULT_PARTIALLY_VALID = 3;
+    public static final int NETWORK_VALIDATION_RESULT_SKIPPED = 4;
+
     private int mMessageId;
     private int mApnType;
     private boolean mIsHandover;
@@ -49,11 +64,20 @@ public class MetricsAtom {
     private String mIwlanErrorWrappedStackFirstFrame;
     private int mErrorCountOfSameCause;
     private boolean mIsNetworkValidated;
+    private int mTriggerReason;
+    private int mValidationResult;
+    private int mValidationTransportType;
+    private int mValidationDurationMills;
+    private long mValidationStartTimeMills;
 
     public void setMessageId(int messageId) {
         this.mMessageId = messageId;
     }
 
+    public int getMessageId() {
+        return mMessageId;
+    }
+
     public void setApnType(int apnType) {
         this.mApnType = apnType;
     }
@@ -164,6 +188,46 @@ public class MetricsAtom {
         mIsNetworkValidated = isNetworkValidated;
     }
 
+    public void setTriggerReason(int reason) {
+        mTriggerReason = reason;
+    }
+
+    public int getTriggerReason() {
+        return mTriggerReason;
+    }
+
+    public void setValidationResult(int validationResult) {
+        mValidationResult = validationResult;
+    }
+
+    public int getValidationResult() {
+        return mValidationResult;
+    }
+
+    public void setValidationTransportType(int transportType) {
+        mValidationTransportType = transportType;
+    }
+
+    public int getValidationTransportType() {
+        return mValidationTransportType;
+    }
+
+    public void setValidationDurationMills(int validationDurationMills) {
+        mValidationDurationMills = validationDurationMills;
+    }
+
+    public int getValidationDurationMills() {
+        return mValidationDurationMills;
+    }
+
+    public void setValidationStartTimeMills(long validationStartTimeMills) {
+        mValidationStartTimeMills = validationStartTimeMills;
+    }
+
+    public long getValidationStartTimeMills() {
+        return mValidationStartTimeMills;
+    }
+
     public void sendMetricsData() {
         if (mMessageId == IwlanStatsLog.IWLAN_SETUP_DATA_CALL_RESULT_REPORTED) {
             Log.d(TAG, "Send metrics data IWLAN_SETUP_DATA_CALL_RESULT_REPORTED");
@@ -197,6 +261,15 @@ public class MetricsAtom {
                     mIsNetworkConnected,
                     mTransportType,
                     mWifiSignalValue);
+        } else if (mMessageId
+                == IwlanStatsLog.IWLAN_UNDERLYING_NETWORK_VALIDATION_RESULT_REPORTED) {
+            Log.d(TAG, "Send metrics data IWLAN_UNDERLYING_NETWORK_VALIDATION_RESULT_REPORTED");
+            IwlanStatsLog.write(
+                    mMessageId,
+                    mTriggerReason,
+                    mValidationResult,
+                    mValidationTransportType,
+                    mValidationDurationMills);
         } else {
             Log.d("IwlanMetrics", "Invalid Message ID: " + mMessageId);
         }
diff --git a/sysconfig_com.google.android.iwlan.xml b/sysconfig_com.google.android.iwlan.xml
new file mode 100644
index 0000000..54d2d3c
--- /dev/null
+++ b/sysconfig_com.google.android.iwlan.xml
@@ -0,0 +1,4 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<config>
+    <allow-in-power-save package="com.google.android.iwlan" />
+</config>
diff --git a/test/com/google/android/iwlan/ErrorPolicyManagerTest.java b/test/com/google/android/iwlan/ErrorPolicyManagerTest.java
index 95e178c..c3df454 100644
--- a/test/com/google/android/iwlan/ErrorPolicyManagerTest.java
+++ b/test/com/google/android/iwlan/ErrorPolicyManagerTest.java
@@ -27,7 +27,6 @@ import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.eq;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.spy;
-import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
@@ -775,7 +774,7 @@ public class ErrorPolicyManagerTest {
                 .obtainMessage(IwlanEventListener.WIFI_DISABLE_EVENT)
                 .sendToTarget();
         advanceClockByTimeMs(500);
-        verify(mMockDataServiceProvider, times(1)).notifyApnUnthrottled(eq(apn));
+        verify(mMockDataServiceProvider).notifyApnUnthrottled(eq(apn));
 
         boolean bringUpTunnel = mErrorPolicyManager.canBringUpTunnel(apn);
         assertTrue(bringUpTunnel);
@@ -830,7 +829,7 @@ public class ErrorPolicyManagerTest {
                 .obtainMessage(IwlanEventListener.WIFI_CALLING_DISABLE_EVENT)
                 .sendToTarget();
         advanceClockByTimeMs(500);
-        verify(mMockDataServiceProvider, times(1)).notifyApnUnthrottled(eq(apn));
+        verify(mMockDataServiceProvider).notifyApnUnthrottled(eq(apn));
 
         boolean bringUpTunnel = mErrorPolicyManager.canBringUpTunnel(apn);
         assertTrue(bringUpTunnel);
@@ -885,7 +884,7 @@ public class ErrorPolicyManagerTest {
                 .obtainMessage(IwlanEventListener.APM_ENABLE_EVENT)
                 .sendToTarget();
         advanceClockByTimeMs(500);
-        verify(mMockDataServiceProvider, times(1)).notifyApnUnthrottled(eq(apn));
+        verify(mMockDataServiceProvider).notifyApnUnthrottled(eq(apn));
 
         boolean bringUpTunnel = mErrorPolicyManager.canBringUpTunnel(apn);
         assertTrue(bringUpTunnel);
@@ -943,7 +942,7 @@ public class ErrorPolicyManagerTest {
                 .obtainMessage(IwlanEventListener.WIFI_AP_CHANGED_EVENT)
                 .sendToTarget();
         advanceClockByTimeMs(500);
-        verify(mMockDataServiceProvider, times(1)).notifyApnUnthrottled(eq(apn));
+        verify(mMockDataServiceProvider).notifyApnUnthrottled(eq(apn));
 
         boolean bringUpTunnel = mErrorPolicyManager.canBringUpTunnel(apn);
         assertTrue(bringUpTunnel);
@@ -1052,9 +1051,9 @@ public class ErrorPolicyManagerTest {
 
         // IKE_PROTOCOL_ERROR_TYPE(24) and retryArray = 4,8,16
         IwlanError iwlanError = buildIwlanIkeAuthFailedError();
-        long time = mErrorPolicyManager.reportIwlanError(apn, iwlanError, 2);
+        mErrorPolicyManager.reportIwlanError(apn, iwlanError, 2);
 
-        time = Math.round((double) mErrorPolicyManager.getRemainingRetryTimeMs(apn) / 1000);
+        long time = Math.round((double) mErrorPolicyManager.getRemainingRetryTimeMs(apn) / 1000);
         assertEquals(time, 2);
 
         // advanceClockByTimeMs for 2 seconds and make sure that we can bring up tunnel after 2 secs
@@ -1070,7 +1069,7 @@ public class ErrorPolicyManagerTest {
         bringUpTunnel = mErrorPolicyManager.canBringUpTunnel(apn);
         assertFalse(bringUpTunnel);
 
-        time = mErrorPolicyManager.reportIwlanError(apn, iwlanError, 5);
+        mErrorPolicyManager.reportIwlanError(apn, iwlanError, 5);
         time = Math.round((double) mErrorPolicyManager.getRemainingRetryTimeMs(apn) / 1000);
         assertEquals(time, 5);
 
diff --git a/test/com/google/android/iwlan/IwlanBroadcastReceiverTest.java b/test/com/google/android/iwlan/IwlanBroadcastReceiverTest.java
index 11b76d5..c11b3ba 100644
--- a/test/com/google/android/iwlan/IwlanBroadcastReceiverTest.java
+++ b/test/com/google/android/iwlan/IwlanBroadcastReceiverTest.java
@@ -18,21 +18,15 @@ package com.google.android.iwlan;
 
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.mockitoSession;
 
-import static org.mockito.ArgumentMatchers.any;
-import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.Mockito.eq;
 import static org.mockito.Mockito.lenient;
-import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 
 import android.content.Context;
 import android.content.Intent;
-import android.net.Network;
 import android.net.wifi.WifiManager;
 import android.telephony.CarrierConfigManager;
 import android.telephony.SubscriptionManager;
-import android.telephony.TelephonyManager;
-import android.telephony.data.ApnSetting;
 
 import com.google.android.iwlan.epdg.EpdgSelector;
 
@@ -47,23 +41,11 @@ public class IwlanBroadcastReceiverTest {
     private static final String TAG = "IwlanBroadcastReceiverTest";
     private IwlanBroadcastReceiver mBroadcastReceiver;
 
-    private static final String ACTION_CARRIER_SIGNAL_PCO_VALUE =
-            TelephonyManager.ACTION_CARRIER_SIGNAL_PCO_VALUE;
-    private static final String EXTRA_APN_TYPE_INT_KEY = TelephonyManager.EXTRA_APN_TYPE;
-    private static final String EXTRA_PCO_ID_KEY = TelephonyManager.EXTRA_PCO_ID;
-    private static final String EXTRA_PCO_VALUE_KEY = TelephonyManager.EXTRA_PCO_VALUE;
-
-    private static final String TEST_PCO_STRING = "testPcoData";
-    private final byte[] pcoData = TEST_PCO_STRING.getBytes();
     private static final int TEST_SUB_ID = 5;
     private static final int TEST_SLOT_ID = 6;
-    private static final int TEST_PCO_ID_I_PV_6 = 0xFF01;
-    private static final int TEST_PCO_ID_I_PV_4 = 0xFF02;
 
     MockitoSession mStaticMockSession;
     @Mock private Context mMockContext;
-    @Mock private Network mMockNetwork;
-    @Mock private EpdgSelector mMockEpdgSelector;
     @Mock private IwlanEventListener mMockIwlanEventListener;
 
     @Before
@@ -83,19 +65,10 @@ public class IwlanBroadcastReceiverTest {
 
         lenient().when(IwlanDataService.getContext()).thenReturn(mMockContext);
 
-        lenient()
-                .when(EpdgSelector.getSelectorInstance(eq(mMockContext), eq(TEST_SLOT_ID)))
-                .thenReturn(mMockEpdgSelector);
-
         lenient()
                 .when(IwlanEventListener.getInstance(eq(mMockContext), eq(TEST_SLOT_ID)))
                 .thenReturn(mMockIwlanEventListener);
 
-        IwlanCarrierConfig.putTestConfigInt(
-                CarrierConfigManager.Iwlan.KEY_EPDG_PCO_ID_IPV6_INT, TEST_PCO_ID_I_PV_6);
-        IwlanCarrierConfig.putTestConfigInt(
-                CarrierConfigManager.Iwlan.KEY_EPDG_PCO_ID_IPV4_INT, TEST_PCO_ID_I_PV_4);
-
         // New BroadcastReceiver object
         mBroadcastReceiver = new IwlanBroadcastReceiver();
     }
@@ -105,46 +78,6 @@ public class IwlanBroadcastReceiverTest {
         mStaticMockSession.finishMocking();
     }
 
-    @Test
-    public void testOnReceiveNoPcoData() throws Exception {
-        onReceiveMethodWithArgs(ApnSetting.TYPE_IMS, TEST_PCO_ID_I_PV_6, null);
-
-        // Verify the called times of setPcoData method
-        verify(mMockEpdgSelector, times(0)).setPcoData(anyInt(), any(byte[].class));
-    }
-
-    @Test
-    public void testOnReceiveIPv6Pass() throws Exception {
-        onReceiveMethodWithArgs(ApnSetting.TYPE_IMS, TEST_PCO_ID_I_PV_6);
-
-        // Verify the called times of setPcoData method
-        verify(mMockEpdgSelector, times(1)).setPcoData(TEST_PCO_ID_I_PV_6, pcoData);
-    }
-
-    @Test
-    public void testOnReceiveIPv4Pass() throws Exception {
-        onReceiveMethodWithArgs(ApnSetting.TYPE_IMS, TEST_PCO_ID_I_PV_4);
-
-        // Verify the called times of setPcoData method
-        verify(mMockEpdgSelector, times(1)).setPcoData(TEST_PCO_ID_I_PV_4, pcoData);
-    }
-
-    @Test
-    public void testOnReceiveIncorrectApnType() throws Exception {
-        onReceiveMethodWithArgs(ApnSetting.TYPE_DEFAULT, TEST_PCO_ID_I_PV_6);
-
-        // Verify the called times of setPcoData method
-        verify(mMockEpdgSelector, times(0)).setPcoData(TEST_PCO_ID_I_PV_6, pcoData);
-    }
-
-    @Test
-    public void testOnReceiveMethodIncorrectPcoId() throws Exception {
-        onReceiveMethodWithArgs(ApnSetting.TYPE_IMS, 0xFF00);
-
-        // Verify the called times of setPcoData method
-        verify(mMockEpdgSelector, times(0)).setPcoData(0xFF00, pcoData);
-    }
-
     @Test
     public void testCarrierConfigChanged() throws Exception {
         final Intent intent = new Intent(CarrierConfigManager.ACTION_CARRIER_CONFIG_CHANGED);
@@ -166,27 +99,14 @@ public class IwlanBroadcastReceiverTest {
 
         verify(mMockIwlanEventListener).onBroadcastReceived(intent);
     }
-    private void onReceiveMethodWithArgs(int apnType, int pcoId) {
-        // Create intent object
-        final Intent mIntent = new Intent(ACTION_CARRIER_SIGNAL_PCO_VALUE);
-        mIntent.putExtra(SubscriptionManager.EXTRA_SUBSCRIPTION_INDEX, TEST_SUB_ID);
-        mIntent.putExtra(EXTRA_APN_TYPE_INT_KEY, apnType);
-        mIntent.putExtra(EXTRA_PCO_ID_KEY, pcoId);
-        mIntent.putExtra(EXTRA_PCO_VALUE_KEY, pcoData);
-
-        // Trigger onReceive method
-        mBroadcastReceiver.onReceive(mMockContext, mIntent);
-    }
 
-    private void onReceiveMethodWithArgs(int apnType, int pcoId, byte[] pcoData) {
-        // Create intent object
-        final Intent mIntent = new Intent(ACTION_CARRIER_SIGNAL_PCO_VALUE);
-        mIntent.putExtra(SubscriptionManager.EXTRA_SUBSCRIPTION_INDEX, TEST_SUB_ID);
-        mIntent.putExtra(EXTRA_APN_TYPE_INT_KEY, apnType);
-        mIntent.putExtra(EXTRA_PCO_ID_KEY, pcoId);
-        mIntent.putExtra(EXTRA_PCO_VALUE_KEY, pcoData);
+    @Test
+    public void testScreenOn_shouldSendToListener() throws Exception {
+        final Intent intent = new Intent(Intent.ACTION_SCREEN_ON);
 
-        // Trigger onReceive method
-        mBroadcastReceiver.onReceive(mMockContext, mIntent);
+        // Trigger broadcast
+        mBroadcastReceiver.onReceive(mMockContext, intent);
+
+        verify(mMockIwlanEventListener).onBroadcastReceived(intent);
     }
 }
diff --git a/test/com/google/android/iwlan/IwlanDataServiceTest.java b/test/com/google/android/iwlan/IwlanDataServiceTest.java
index 07f7ad5..417858c 100644
--- a/test/com/google/android/iwlan/IwlanDataServiceTest.java
+++ b/test/com/google/android/iwlan/IwlanDataServiceTest.java
@@ -21,6 +21,7 @@ import static android.net.NetworkCapabilities.TRANSPORT_ETHERNET;
 import static android.net.NetworkCapabilities.TRANSPORT_WIFI;
 import static android.net.ipsec.ike.ike3gpp.Ike3gppParams.PDU_SESSION_ID_UNSET;
 import static android.telephony.TelephonyManager.CALL_STATE_IDLE;
+import static android.telephony.TelephonyManager.CALL_STATE_OFFHOOK;
 import static android.telephony.TelephonyManager.CALL_STATE_RINGING;
 import static android.telephony.TelephonyManager.NETWORK_TYPE_BITMASK_LTE;
 import static android.telephony.TelephonyManager.NETWORK_TYPE_BITMASK_NR;
@@ -90,12 +91,10 @@ import android.telephony.ims.ImsMmTelManager;
 import com.google.android.iwlan.IwlanDataService.IwlanDataServiceProvider;
 import com.google.android.iwlan.IwlanDataService.IwlanDataServiceProvider.IwlanTunnelCallback;
 import com.google.android.iwlan.IwlanDataService.IwlanDataServiceProvider.TunnelState;
-import com.google.android.iwlan.epdg.EpdgSelector;
 import com.google.android.iwlan.epdg.EpdgTunnelManager;
 import com.google.android.iwlan.epdg.NetworkSliceSelectionAssistanceInformation;
 import com.google.android.iwlan.epdg.TunnelLinkProperties;
 import com.google.android.iwlan.epdg.TunnelSetupRequest;
-import com.google.android.iwlan.flags.FeatureFlags;
 import com.google.android.iwlan.proto.MetricsAtom;
 
 import org.junit.After;
@@ -140,16 +139,16 @@ public class IwlanDataServiceTest {
     @Mock private IwlanDataServiceProvider mMockIwlanDataServiceProvider;
     @Mock private Network mMockNetwork;
     @Mock private TunnelLinkProperties mMockTunnelLinkProperties;
+    @Mock private TunnelMetricsInterface.OnOpenedMetrics mMockOnOpenedMetrics;
+    @Mock private TunnelMetricsInterface.OnClosedMetrics mMockOnClosedMetrics;
     @Mock private ErrorPolicyManager mMockErrorPolicyManager;
     @Mock private ImsManager mMockImsManager;
     @Mock private ImsMmTelManager mMockImsMmTelManager;
     @Mock private TelephonyManager mMockTelephonyManager;
-    @Mock private EpdgSelector mMockEpdgSelector;
     @Mock private LinkAddress mMockIPv4LinkAddress;
     @Mock private LinkAddress mMockIPv6LinkAddress;
     @Mock private Inet4Address mMockInet4Address;
     @Mock private Inet6Address mMockInet6Address;
-    @Mock private FeatureFlags mFakeFeatureFlags;
 
     MockitoSession mStaticMockSession;
 
@@ -165,12 +164,6 @@ public class IwlanDataServiceTest {
 
     private final class IwlanDataServiceCallback extends IDataServiceCallback.Stub {
 
-        private final String mTag;
-
-        IwlanDataServiceCallback(String tag) {
-            mTag = tag;
-        }
-
         @Override
         public void onSetupDataCallComplete(
                 @DataServiceCallback.ResultCode int resultCode, DataCallResponse response) {}
@@ -214,7 +207,6 @@ public class IwlanDataServiceTest {
 
         mStaticMockSession =
                 mockitoSession()
-                        .mockStatic(EpdgSelector.class)
                         .mockStatic(EpdgTunnelManager.class)
                         .mockStatic(ErrorPolicyManager.class)
                         .mockStatic(IwlanBroadcastReceiver.class)
@@ -266,13 +258,10 @@ public class IwlanDataServiceTest {
 
         when(mMockImsMmTelManager.isVoWiFiSettingEnabled()).thenReturn(false);
 
-        when(EpdgSelector.getSelectorInstance(eq(mMockContext), eq(DEFAULT_SLOT_INDEX)))
-                .thenReturn(mMockEpdgSelector);
-
         when(mMockIPv4LinkAddress.getAddress()).thenReturn(mMockInet4Address);
         when(mMockIPv6LinkAddress.getAddress()).thenReturn(mMockInet6Address);
 
-        mIwlanDataService = spy(new IwlanDataService(mFakeFeatureFlags));
+        mIwlanDataService = spy(new IwlanDataService());
 
         // Injects the test looper into the IwlanDataServiceHandler
         doReturn(mTestLooper.getLooper()).when(mIwlanDataService).getLooper();
@@ -294,6 +283,8 @@ public class IwlanDataServiceTest {
         when(mMockTunnelLinkProperties.ifaceName()).thenReturn("mockipsec0");
 
         mockCarrierConfigForN1Mode(true);
+
+        doNothing().when(mMockEpdgTunnelManager).close();
     }
 
     private void moveTimeForwardAndDispatch(long milliSeconds) {
@@ -374,7 +365,7 @@ public class IwlanDataServiceTest {
         Network newNetwork = createMockNetwork(mLinkProperties);
         onSystemDefaultNetworkConnected(
                 newNetwork, mLinkProperties, TRANSPORT_WIFI, INVALID_SUB_INDEX);
-        verify(mMockEpdgTunnelManager, times(1)).updateNetwork(eq(newNetwork), eq(mLinkProperties));
+        verify(mMockEpdgTunnelManager).updateNetwork(eq(newNetwork), eq(mLinkProperties));
 
         onSystemDefaultNetworkLost();
         onSystemDefaultNetworkConnected(
@@ -395,8 +386,7 @@ public class IwlanDataServiceTest {
         newLinkProperties.addLinkAddress(mMockIPv6LinkAddress);
 
         networkCallback.onLinkPropertiesChanged(mMockNetwork, newLinkProperties);
-        verify(mMockEpdgTunnelManager, times(1))
-                .updateNetwork(eq(mMockNetwork), eq(newLinkProperties));
+        verify(mMockEpdgTunnelManager).updateNetwork(eq(mMockNetwork), eq(newLinkProperties));
     }
 
     @Test
@@ -439,8 +429,7 @@ public class IwlanDataServiceTest {
         assertNotEquals(mLinkProperties, newLinkProperties);
 
         networkCallback.onLinkPropertiesChanged(mMockNetwork, newLinkProperties);
-        verify(mMockEpdgTunnelManager, times(1))
-                .updateNetwork(eq(mMockNetwork), eq(newLinkProperties));
+        verify(mMockEpdgTunnelManager).updateNetwork(eq(mMockNetwork), eq(newLinkProperties));
     }
 
     @Test
@@ -468,10 +457,8 @@ public class IwlanDataServiceTest {
         newLinkProperties.addLinkAddress(mMockIPv6LinkAddress);
 
         networkCallback.onLinkPropertiesChanged(mMockNetwork, newLinkProperties);
-        verify(mMockEpdgTunnelManager, times(1))
-                .updateNetwork(eq(mMockNetwork), eq(newLinkProperties));
-        verify(mMockEpdgTunnelManager, never())
-                .closeTunnel(any(), anyBoolean(), any(), any(), anyInt());
+        verify(mMockEpdgTunnelManager).updateNetwork(eq(mMockNetwork), eq(newLinkProperties));
+        verify(mMockEpdgTunnelManager, never()).closeTunnel(any(), anyBoolean(), any(), anyInt());
     }
 
     @Test
@@ -535,7 +522,7 @@ public class IwlanDataServiceTest {
                 newNetwork, mLinkProperties, TRANSPORT_CELLULAR, DEFAULT_SUB_INDEX);
 
         mIwlanDataService
-                .mIwlanDataServiceHandler
+                .mHandler
                 .obtainMessage(
                         IwlanEventListener.CROSS_SIM_CALLING_ENABLE_EVENT,
                         DEFAULT_SLOT_INDEX,
@@ -554,10 +541,10 @@ public class IwlanDataServiceTest {
         Network newNetwork = createMockNetwork(mLinkProperties);
         onSystemDefaultNetworkConnected(
                 newNetwork, mLinkProperties, TRANSPORT_CELLULAR, DEFAULT_SUB_INDEX + 1);
-        verify(mMockEpdgTunnelManager, times(1)).updateNetwork(eq(newNetwork), eq(mLinkProperties));
+        verify(mMockEpdgTunnelManager).updateNetwork(eq(newNetwork), eq(mLinkProperties));
 
         mIwlanDataService
-                .mIwlanDataServiceHandler
+                .mHandler
                 .obtainMessage(
                         IwlanEventListener.CROSS_SIM_CALLING_ENABLE_EVENT,
                         DEFAULT_SLOT_INDEX,
@@ -573,7 +560,7 @@ public class IwlanDataServiceTest {
         onSystemDefaultNetworkLost();
 
         mIwlanDataService
-                .mIwlanDataServiceHandler
+                .mHandler
                 .obtainMessage(
                         IwlanEventListener.CROSS_SIM_CALLING_ENABLE_EVENT,
                         DEFAULT_SLOT_INDEX,
@@ -606,7 +593,7 @@ public class IwlanDataServiceTest {
         when(mMockIwlanDataServiceProvider.getSlotIndex()).thenReturn(DEFAULT_SLOT_INDEX);
         mIwlanDataService.removeDataServiceProvider(mMockIwlanDataServiceProvider);
         mTestLooper.dispatchAll();
-        verify(mIwlanDataService, times(1)).deinitNetworkCallback();
+        verify(mIwlanDataService).deinitNetworkCallback();
         mIwlanDataService.onCreateDataServiceProvider(DEFAULT_SLOT_INDEX);
         mTestLooper.dispatchAll();
     }
@@ -619,7 +606,7 @@ public class IwlanDataServiceTest {
         List<InetAddress> mGatewayAddressList;
         List<InetAddress> mPCSFAddressList;
 
-        IwlanDataServiceCallback callback = new IwlanDataServiceCallback("requestDataCallList");
+        IwlanDataServiceCallback callback = new IwlanDataServiceCallback();
         TunnelLinkProperties mLinkProperties = createTunnelLinkProperties();
         mSpyIwlanDataServiceProvider.setTunnelState(
                 dp,
@@ -672,7 +659,7 @@ public class IwlanDataServiceTest {
 
     @Test
     public void testRequestDataCallListEmpty() throws Exception {
-        IwlanDataServiceCallback callback = new IwlanDataServiceCallback("requestDataCallList");
+        IwlanDataServiceCallback callback = new IwlanDataServiceCallback();
         mSpyIwlanDataServiceProvider.requestDataCallList(new DataServiceCallback(callback));
         mTestLooper.dispatchAll();
 
@@ -763,18 +750,16 @@ public class IwlanDataServiceTest {
         mTestLooper.dispatchAll();
 
         /* Check bringUpTunnel() is called. */
-        verify(mMockEpdgTunnelManager, times(1))
-                .bringUpTunnel(
-                        any(TunnelSetupRequest.class),
-                        any(IwlanTunnelCallback.class),
-                        any(IwlanTunnelMetricsImpl.class));
+        verify(mMockEpdgTunnelManager)
+                .bringUpTunnel(any(TunnelSetupRequest.class), any(IwlanTunnelCallback.class));
 
         /* Check callback result is RESULT_SUCCESS when onOpened() is called. */
+        stubMockOnOpenedMetrics();
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties);
+                .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties, mMockOnOpenedMetrics);
         mTestLooper.dispatchAll();
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_SUCCESS), any(DataCallResponse.class));
     }
@@ -801,7 +786,7 @@ public class IwlanDataServiceTest {
                 mMockDataServiceCallback);
         mTestLooper.dispatchAll();
 
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_ERROR_INVALID_ARG), isNull());
     }
@@ -829,11 +814,8 @@ public class IwlanDataServiceTest {
         mTestLooper.dispatchAll();
 
         /* Check bringUpTunnel() is called. */
-        verify(mMockEpdgTunnelManager, times(1))
-                .bringUpTunnel(
-                        any(TunnelSetupRequest.class),
-                        any(IwlanTunnelCallback.class),
-                        any(IwlanTunnelMetricsImpl.class));
+        verify(mMockEpdgTunnelManager)
+                .bringUpTunnel(any(TunnelSetupRequest.class), any(IwlanTunnelCallback.class));
 
         /* Check callback result is RESULT_SUCCESS when onOpened() is called. */
         TunnelLinkProperties tp = createTunnelLinkProperties();
@@ -841,9 +823,12 @@ public class IwlanDataServiceTest {
         ArgumentCaptor<DataCallResponse> dataCallResponseCaptor =
                 ArgumentCaptor.forClass(DataCallResponse.class);
 
-        mSpyIwlanDataServiceProvider.getIwlanTunnelCallback().onOpened(TEST_APN_NAME, tp);
+        stubMockOnOpenedMetrics();
+        mSpyIwlanDataServiceProvider
+                .getIwlanTunnelCallback()
+                .onOpened(TEST_APN_NAME, tp, mMockOnOpenedMetrics);
         mTestLooper.dispatchAll();
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_SUCCESS), dataCallResponseCaptor.capture());
 
@@ -875,20 +860,19 @@ public class IwlanDataServiceTest {
                 mMockDataServiceCallback);
         mTestLooper.dispatchAll();
         /* Check closeTunnel() is called. */
-        verify(mMockEpdgTunnelManager, times(1))
+        verify(mMockEpdgTunnelManager)
                 .closeTunnel(
                         eq(TEST_APN_NAME),
                         eq(false),
                         any(IwlanTunnelCallback.class),
-                        any(IwlanTunnelMetricsImpl.class),
                         eq(BRINGDOWN_REASON_DEACTIVATE_DATA_CALL));
 
         /* Check callback result is RESULT_SUCCESS when onClosed() is called. */
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR));
+                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onDeactivateDataCallComplete(eq(DataServiceCallback.RESULT_SUCCESS));
     }
 
@@ -916,20 +900,19 @@ public class IwlanDataServiceTest {
 
         moveTimeForwardAndDispatch(50);
         /* Check closeTunnel() is called. */
-        verify(mMockEpdgTunnelManager, times(1))
+        verify(mMockEpdgTunnelManager)
                 .closeTunnel(
                         eq(TEST_APN_NAME),
                         eq(true) /* forceClose */,
                         any(IwlanTunnelCallback.class),
-                        any(IwlanTunnelMetricsImpl.class),
                         eq(BRINGDOWN_REASON_DEACTIVATE_DATA_CALL));
 
         /* Check callback result is RESULT_SUCCESS when onClosed() is called. */
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR));
+                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onDeactivateDataCallComplete(eq(DataServiceCallback.RESULT_SUCCESS));
     }
 
@@ -964,25 +947,23 @@ public class IwlanDataServiceTest {
                         eq(TEST_APN_NAME),
                         anyBoolean(),
                         any(IwlanTunnelCallback.class),
-                        any(IwlanTunnelMetricsImpl.class),
                         eq(BRINGDOWN_REASON_DEACTIVATE_DATA_CALL));
 
         moveTimeForwardAndDispatch(50);
         /* Check closeTunnel() is called. */
-        verify(mMockEpdgTunnelManager, times(1))
+        verify(mMockEpdgTunnelManager)
                 .closeTunnel(
                         eq(TEST_APN_NAME),
                         eq(true) /* forceClose */,
                         any(IwlanTunnelCallback.class),
-                        any(IwlanTunnelMetricsImpl.class),
                         eq(BRINGDOWN_REASON_DEACTIVATE_DATA_CALL));
 
         /* Check callback result is RESULT_SUCCESS when onClosed() is called. */
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR));
+                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onDeactivateDataCallComplete(eq(DataServiceCallback.RESULT_SUCCESS));
     }
 
@@ -1026,32 +1007,24 @@ public class IwlanDataServiceTest {
         /* Check closeTunnel() is not called. */
         verify(mMockEpdgTunnelManager, never())
                 .closeTunnel(
-                        eq(TEST_APN_NAME),
-                        anyBoolean(),
-                        any(IwlanTunnelCallback.class),
-                        any(IwlanTunnelMetricsImpl.class),
-                        anyInt());
+                        eq(TEST_APN_NAME), anyBoolean(), any(IwlanTunnelCallback.class), anyInt());
 
         /* Check callback result is RESULT_SUCCESS when onClosed() is called. */
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR));
+                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onDeactivateDataCallComplete(eq(DataServiceCallback.RESULT_SUCCESS));
 
         moveTimeForwardAndDispatch(4000);
 
         verify(mMockEpdgTunnelManager, never())
                 .closeTunnel(
-                        eq(TEST_APN_NAME),
-                        anyBoolean(),
-                        any(IwlanTunnelCallback.class),
-                        any(IwlanTunnelMetricsImpl.class),
-                        anyInt());
+                        eq(TEST_APN_NAME), anyBoolean(), any(IwlanTunnelCallback.class), anyInt());
 
         // No additional callbacks are involved.
-        verify(mMockDataServiceCallback, times(1)).onDeactivateDataCallComplete(anyInt());
+        verify(mMockDataServiceCallback).onDeactivateDataCallComplete(anyInt());
     }
 
     @Test
@@ -1084,13 +1057,13 @@ public class IwlanDataServiceTest {
 
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR));
+                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
 
         ArgumentCaptor<DataCallResponse> dataCallResponseCaptor =
                 ArgumentCaptor.forClass(DataCallResponse.class);
 
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_SUCCESS), dataCallResponseCaptor.capture());
 
@@ -1134,13 +1107,13 @@ public class IwlanDataServiceTest {
 
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR));
+                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
 
         ArgumentCaptor<DataCallResponse> dataCallResponseCaptor =
                 ArgumentCaptor.forClass(DataCallResponse.class);
 
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_SUCCESS), dataCallResponseCaptor.capture());
 
@@ -1164,7 +1137,7 @@ public class IwlanDataServiceTest {
 
         // APN = IMS, in idle call state
         mIwlanDataService
-                .mIwlanDataServiceHandler
+                .mHandler
                 .obtainMessage(
                         IwlanEventListener.CALL_STATE_CHANGED_EVENT,
                         DEFAULT_SLOT_INDEX,
@@ -1193,12 +1166,12 @@ public class IwlanDataServiceTest {
 
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR));
+                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
 
         ArgumentCaptor<DataCallResponse> dataCallResponseCaptor =
                 ArgumentCaptor.forClass(DataCallResponse.class);
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_SUCCESS), dataCallResponseCaptor.capture());
         DataCallResponse dataCallResponse = dataCallResponseCaptor.getValue();
@@ -1220,7 +1193,7 @@ public class IwlanDataServiceTest {
 
         // APN = Emergency, in idle call state
         mIwlanDataService
-                .mIwlanDataServiceHandler
+                .mHandler
                 .obtainMessage(
                         IwlanEventListener.CALL_STATE_CHANGED_EVENT,
                         DEFAULT_SLOT_INDEX,
@@ -1249,12 +1222,12 @@ public class IwlanDataServiceTest {
 
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR));
+                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
 
         ArgumentCaptor<DataCallResponse> dataCallResponseCaptor =
                 ArgumentCaptor.forClass(DataCallResponse.class);
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_SUCCESS), dataCallResponseCaptor.capture());
         DataCallResponse dataCallResponse = dataCallResponseCaptor.getValue();
@@ -1276,7 +1249,7 @@ public class IwlanDataServiceTest {
 
         // APN = IMS, in call
         mIwlanDataService
-                .mIwlanDataServiceHandler
+                .mHandler
                 .obtainMessage(
                         IwlanEventListener.CALL_STATE_CHANGED_EVENT,
                         DEFAULT_SLOT_INDEX,
@@ -1305,12 +1278,12 @@ public class IwlanDataServiceTest {
 
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR));
+                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
 
         ArgumentCaptor<DataCallResponse> dataCallResponseCaptor =
                 ArgumentCaptor.forClass(DataCallResponse.class);
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_SUCCESS), dataCallResponseCaptor.capture());
         DataCallResponse dataCallResponse = dataCallResponseCaptor.getValue();
@@ -1332,7 +1305,7 @@ public class IwlanDataServiceTest {
 
         // APN = Emergency, in call
         mIwlanDataService
-                .mIwlanDataServiceHandler
+                .mHandler
                 .obtainMessage(
                         IwlanEventListener.CALL_STATE_CHANGED_EVENT,
                         DEFAULT_SLOT_INDEX,
@@ -1361,12 +1334,12 @@ public class IwlanDataServiceTest {
 
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR));
+                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
 
         ArgumentCaptor<DataCallResponse> dataCallResponseCaptor =
                 ArgumentCaptor.forClass(DataCallResponse.class);
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_SUCCESS), dataCallResponseCaptor.capture());
         DataCallResponse dataCallResponse = dataCallResponseCaptor.getValue();
@@ -1385,7 +1358,7 @@ public class IwlanDataServiceTest {
         networkCallback.onLinkPropertiesChanged(mMockNetwork, mLinkProperties);
 
         mIwlanDataService
-                .mIwlanDataServiceHandler
+                .mHandler
                 .obtainMessage(
                         IwlanEventListener.CARRIER_CONFIG_CHANGED_EVENT,
                         DEFAULT_SLOT_INDEX,
@@ -1393,7 +1366,7 @@ public class IwlanDataServiceTest {
                 .sendToTarget();
 
         mIwlanDataService
-                .mIwlanDataServiceHandler
+                .mHandler
                 .obtainMessage(
                         IwlanEventListener.WIFI_CALLING_ENABLE_EVENT,
                         DEFAULT_SLOT_INDEX,
@@ -1412,24 +1385,7 @@ public class IwlanDataServiceTest {
            1. Network connected, CarrierConfig ready, WifiCallingSetting enabled
            2. Connection ipFamily changed.
         */
-        verify(mMockEpdgSelector, times(2))
-                .getValidatedServerList(
-                        eq(0),
-                        eq(EpdgSelector.PROTO_FILTER_IPV4V6),
-                        eq(EpdgSelector.SYSTEM_PREFERRED),
-                        eq(false),
-                        eq(false),
-                        eq(mMockNetwork),
-                        isNull());
-        verify(mMockEpdgSelector, times(2))
-                .getValidatedServerList(
-                        eq(0),
-                        eq(EpdgSelector.PROTO_FILTER_IPV4V6),
-                        eq(EpdgSelector.SYSTEM_PREFERRED),
-                        eq(false),
-                        eq(true),
-                        eq(mMockNetwork),
-                        isNull());
+        verify(mMockEpdgTunnelManager, times(2)).prefetchEpdgServerList(mMockNetwork, false);
     }
 
     private void advanceCalendarByTimeMs(long time, Calendar calendar) {
@@ -1580,18 +1536,16 @@ public class IwlanDataServiceTest {
         mTestLooper.dispatchAll();
 
         /* Check bringUpTunnel() is called. */
-        verify(mMockEpdgTunnelManager, times(1))
-                .bringUpTunnel(
-                        any(TunnelSetupRequest.class),
-                        any(IwlanTunnelCallback.class),
-                        any(IwlanTunnelMetricsImpl.class));
+        verify(mMockEpdgTunnelManager)
+                .bringUpTunnel(any(TunnelSetupRequest.class), any(IwlanTunnelCallback.class));
 
         /* Check callback result is RESULT_SUCCESS when onOpened() is called. */
+        stubMockOnOpenedMetrics();
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties);
+                .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties, mMockOnOpenedMetrics);
         mTestLooper.dispatchAll();
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_SUCCESS), any(DataCallResponse.class));
     }
@@ -1731,13 +1685,13 @@ public class IwlanDataServiceTest {
                         eq(TEST_APN_NAME),
                         eq(true),
                         any(IwlanTunnelCallback.class),
-                        any(IwlanTunnelMetricsImpl.class),
                         eq(EpdgTunnelManager.BRINGDOWN_REASON_UNKNOWN));
-        assertNotNull(mIwlanDataService.mIwlanDataServiceHandler);
+        assertNotNull(mIwlanDataService.mHandler);
+        verify(mMockEpdgTunnelManager, times(1)).close();
         // Should not raise NullPointerException
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR));
+                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
     }
 
@@ -1792,7 +1746,10 @@ public class IwlanDataServiceTest {
 
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onClosed(TEST_APN_NAME, new IwlanError(new IkeInternalException(mockException)));
+                .onClosed(
+                        TEST_APN_NAME,
+                        new IwlanError(new IkeInternalException(mockException)),
+                        mMockOnClosedMetrics);
 
         mTestLooper.dispatchAll();
 
@@ -1847,7 +1804,8 @@ public class IwlanDataServiceTest {
                 .getIwlanTunnelCallback()
                 .onClosed(
                         TEST_APN_NAME,
-                        new IwlanError(IwlanError.EPDG_SELECTOR_SERVER_SELECTION_FAILED));
+                        new IwlanError(IwlanError.EPDG_SELECTOR_SERVER_SELECTION_FAILED),
+                        mMockOnClosedMetrics);
 
         mTestLooper.dispatchAll();
 
@@ -1888,7 +1846,10 @@ public class IwlanDataServiceTest {
 
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.IKE_PROTOCOL_EXCEPTION));
+                .onClosed(
+                        TEST_APN_NAME,
+                        new IwlanError(IwlanError.IKE_PROTOCOL_EXCEPTION),
+                        mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
 
         assertEquals(5, metricsAtom.getErrorCountOfSameCause());
@@ -1909,14 +1870,14 @@ public class IwlanDataServiceTest {
                 mMockDataServiceCallback);
         doReturn(true)
                 .when(mMockEpdgTunnelManager)
-                .bringUpTunnel(
-                        any(TunnelSetupRequest.class),
-                        any(IwlanTunnelCallback.class),
-                        any(IwlanTunnelMetricsImpl.class));
+                .bringUpTunnel(any(TunnelSetupRequest.class), any(IwlanTunnelCallback.class));
 
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.IKE_INTERNAL_IO_EXCEPTION));
+                .onClosed(
+                        TEST_APN_NAME,
+                        new IwlanError(IwlanError.IKE_INTERNAL_IO_EXCEPTION),
+                        mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
         verify(mMockDataServiceCallback, atLeastOnce())
                 .onSetupDataCallComplete(
@@ -1938,17 +1899,15 @@ public class IwlanDataServiceTest {
                 mMockDataServiceCallback);
         doReturn(true)
                 .when(mMockEpdgTunnelManager)
-                .bringUpTunnel(
-                        any(TunnelSetupRequest.class),
-                        any(IwlanTunnelCallback.class),
-                        any(IwlanTunnelMetricsImpl.class));
+                .bringUpTunnel(any(TunnelSetupRequest.class), any(IwlanTunnelCallback.class));
         mTestLooper.dispatchAll();
 
         advanceCalendarByTimeMs(setupTime, calendar);
 
+        stubMockOnOpenedMetrics();
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties);
+                .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties, mMockOnOpenedMetrics);
         mTestLooper.dispatchAll();
         verify(mMockDataServiceCallback, atLeastOnce())
                 .onSetupDataCallComplete(
@@ -1958,7 +1917,10 @@ public class IwlanDataServiceTest {
     private void mockUnsolTunnelDown() {
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.IKE_INTERNAL_IO_EXCEPTION));
+                .onClosed(
+                        TEST_APN_NAME,
+                        new IwlanError(IwlanError.IKE_INTERNAL_IO_EXCEPTION),
+                        mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
     }
 
@@ -1973,14 +1935,13 @@ public class IwlanDataServiceTest {
                         eq(TEST_APN_NAME),
                         anyBoolean(),
                         any(IwlanTunnelCallback.class),
-                        any(IwlanTunnelMetricsImpl.class),
                         eq(BRINGDOWN_REASON_DEACTIVATE_DATA_CALL));
 
         advanceCalendarByTimeMs(deactivationTime, calendar);
 
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR));
+                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
         verify(mMockDataServiceCallback, atLeastOnce())
                 .onDeactivateDataCallComplete(eq(DataServiceCallback.RESULT_SUCCESS));
@@ -2016,21 +1977,17 @@ public class IwlanDataServiceTest {
         mTestLooper.dispatchAll();
 
         /* Check bringUpTunnel() is called. */
-        verify(mMockEpdgTunnelManager, times(1))
-                .bringUpTunnel(
-                        any(TunnelSetupRequest.class),
-                        any(IwlanTunnelCallback.class),
-                        any(IwlanTunnelMetricsImpl.class));
+        verify(mMockEpdgTunnelManager)
+                .bringUpTunnel(any(TunnelSetupRequest.class), any(IwlanTunnelCallback.class));
 
         Network newNetwork2 = createMockNetwork(mLinkProperties);
         onSystemDefaultNetworkConnected(
                 newNetwork2, mLinkProperties, TRANSPORT_WIFI, DEFAULT_SUB_INDEX);
-        verify(mMockEpdgTunnelManager, times(1))
+        verify(mMockEpdgTunnelManager)
                 .closeTunnel(
                         any(),
                         anyBoolean(),
                         any(),
-                        any(),
                         eq(BRINGDOWN_REASON_NETWORK_UPDATE_WHEN_TUNNEL_IN_BRINGUP));
     }
 
@@ -2076,14 +2033,21 @@ public class IwlanDataServiceTest {
         IwlanCarrierConfig.putTestConfigBundle(bundle);
     }
 
+    private void sendCallStateChangedEvent(int callState, int slotIndex) {
+        mIwlanDataService
+                .mHandler
+                .obtainMessage(IwlanEventListener.CALL_STATE_CHANGED_EVENT, slotIndex, callState)
+                .sendToTarget();
+    }
+
+    private void sendCallStateChangedEvent(int callState) {
+        sendCallStateChangedEvent(callState, DEFAULT_SLOT_INDEX);
+    }
+
     private void mockCallState(int callState) {
         onSystemDefaultNetworkConnected(TRANSPORT_CELLULAR);
 
-        mIwlanDataService
-                .mIwlanDataServiceHandler
-                .obtainMessage(
-                        IwlanEventListener.CALL_STATE_CHANGED_EVENT, DEFAULT_SLOT_INDEX, callState)
-                .sendToTarget();
+        sendCallStateChangedEvent(callState);
 
         mSpyIwlanDataServiceProvider.setMetricsAtom(
                 TEST_APN_NAME, 64, true, TelephonyManager.NETWORK_TYPE_LTE, false, true, 1);
@@ -2091,7 +2055,7 @@ public class IwlanDataServiceTest {
 
     private void updatePreferredNetworkType(long networkTypeBitmask) {
         mIwlanDataService
-                .mIwlanDataServiceHandler
+                .mHandler
                 .obtainMessage(
                         IwlanEventListener.PREFERRED_NETWORK_TYPE_CHANGED_EVENT,
                         DEFAULT_SLOT_INDEX,
@@ -2131,11 +2095,12 @@ public class IwlanDataServiceTest {
                 IwlanCarrierConfig.KEY_UPDATE_N1_MODE_ON_UI_CHANGE_BOOL, true);
         mockCallState(CALL_STATE_IDLE);
         mockSetupDataCallWithPduSessionId(0);
+        stubMockOnOpenedMetrics();
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties);
+                .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties, mMockOnOpenedMetrics);
         mTestLooper.dispatchAll();
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_SUCCESS), any(DataCallResponse.class));
         updatePreferredNetworkType(NETWORK_TYPE_BITMASK_NR);
@@ -2146,16 +2111,15 @@ public class IwlanDataServiceTest {
                         eq(TEST_APN_NAME),
                         eq(true),
                         any(IwlanTunnelCallback.class),
-                        any(IwlanTunnelMetricsImpl.class),
                         eq(EpdgTunnelManager.BRINGDOWN_REASON_ENABLE_N1_MODE));
 
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR));
+                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
 
         // No additional DataServiceCallback response
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_SUCCESS), any(DataCallResponse.class));
         verify(mMockDataServiceCallback, never()).onDeactivateDataCallComplete(anyInt());
@@ -2171,11 +2135,12 @@ public class IwlanDataServiceTest {
         mockCallState(CALL_STATE_IDLE);
         updatePreferredNetworkType(NETWORK_TYPE_BITMASK_NR);
         mockSetupDataCallWithPduSessionId(5 /* pduSessionId */);
+        stubMockOnOpenedMetrics();
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties);
+                .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties, mMockOnOpenedMetrics);
         mTestLooper.dispatchAll();
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_SUCCESS), any(DataCallResponse.class));
         updatePreferredNetworkType(NETWORK_TYPE_BITMASK_LTE);
@@ -2186,16 +2151,15 @@ public class IwlanDataServiceTest {
                         eq(TEST_APN_NAME),
                         eq(true),
                         any(IwlanTunnelCallback.class),
-                        any(IwlanTunnelMetricsImpl.class),
                         eq(EpdgTunnelManager.BRINGDOWN_REASON_DISABLE_N1_MODE));
 
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR));
+                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
 
         // No additional DataServiceCallback response
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_SUCCESS), any(DataCallResponse.class));
         verify(mMockDataServiceCallback, never()).onDeactivateDataCallComplete(anyInt());
@@ -2212,23 +2176,23 @@ public class IwlanDataServiceTest {
 
         mockCallState(CALL_STATE_RINGING);
         mockSetupDataCallWithPduSessionId(0);
+        stubMockOnOpenedMetrics();
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties);
+                .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties, mMockOnOpenedMetrics);
         mTestLooper.dispatchAll();
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_SUCCESS), any(DataCallResponse.class));
         updatePreferredNetworkType(NETWORK_TYPE_BITMASK_NR);
         updatePreferredNetworkType(NETWORK_TYPE_BITMASK_LTE);
         updatePreferredNetworkType(NETWORK_TYPE_BITMASK_NR);
 
-        verify(mMockEpdgTunnelManager, never())
-                .closeTunnel(any(), anyBoolean(), any(), any(), anyInt());
+        verify(mMockEpdgTunnelManager, never()).closeTunnel(any(), anyBoolean(), any(), anyInt());
 
         // in idle call state
         mIwlanDataService
-                .mIwlanDataServiceHandler
+                .mHandler
                 .obtainMessage(
                         IwlanEventListener.CALL_STATE_CHANGED_EVENT,
                         DEFAULT_SLOT_INDEX,
@@ -2241,16 +2205,15 @@ public class IwlanDataServiceTest {
                         eq(TEST_APN_NAME),
                         eq(true),
                         any(IwlanTunnelCallback.class),
-                        any(IwlanTunnelMetricsImpl.class),
                         eq(EpdgTunnelManager.BRINGDOWN_REASON_ENABLE_N1_MODE));
 
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR));
+                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
 
         // No additional DataServiceCallback response
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_SUCCESS), any(DataCallResponse.class));
         verify(mMockDataServiceCallback, never()).onDeactivateDataCallComplete(anyInt());
@@ -2265,22 +2228,22 @@ public class IwlanDataServiceTest {
 
         mockCallState(CALL_STATE_RINGING);
         mockSetupDataCallWithPduSessionId(0);
+        stubMockOnOpenedMetrics();
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties);
+                .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties, mMockOnOpenedMetrics);
         mTestLooper.dispatchAll();
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_SUCCESS), any(DataCallResponse.class));
         updatePreferredNetworkType(NETWORK_TYPE_BITMASK_NR);
         updatePreferredNetworkType(NETWORK_TYPE_BITMASK_LTE);
 
-        verify(mMockEpdgTunnelManager, never())
-                .closeTunnel(any(), anyBoolean(), any(), any(), anyInt());
+        verify(mMockEpdgTunnelManager, never()).closeTunnel(any(), anyBoolean(), any(), anyInt());
 
         // in idle call state
         mIwlanDataService
-                .mIwlanDataServiceHandler
+                .mHandler
                 .obtainMessage(
                         IwlanEventListener.CALL_STATE_CHANGED_EVENT,
                         DEFAULT_SLOT_INDEX,
@@ -2288,8 +2251,7 @@ public class IwlanDataServiceTest {
                 .sendToTarget();
         mTestLooper.dispatchAll();
 
-        verify(mMockEpdgTunnelManager, never())
-                .closeTunnel(any(), anyBoolean(), any(), any(), anyInt());
+        verify(mMockEpdgTunnelManager, never()).closeTunnel(any(), anyBoolean(), any(), anyInt());
     }
 
     @Test
@@ -2300,17 +2262,17 @@ public class IwlanDataServiceTest {
 
         mockCallState(CALL_STATE_IDLE);
         mockSetupDataCallWithPduSessionId(0);
+        stubMockOnOpenedMetrics();
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties);
+                .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties, mMockOnOpenedMetrics);
         mTestLooper.dispatchAll();
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_SUCCESS), any(DataCallResponse.class));
         updatePreferredNetworkType(NETWORK_TYPE_BITMASK_NR);
 
-        verify(mMockEpdgTunnelManager, never())
-                .closeTunnel(any(), anyBoolean(), any(), any(), anyInt());
+        verify(mMockEpdgTunnelManager, never()).closeTunnel(any(), anyBoolean(), any(), anyInt());
     }
 
     @Test
@@ -2321,17 +2283,17 @@ public class IwlanDataServiceTest {
 
         mockCallState(CALL_STATE_IDLE);
         mockSetupDataCallWithPduSessionId(0);
+        stubMockOnOpenedMetrics();
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties);
+                .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties, mMockOnOpenedMetrics);
         mTestLooper.dispatchAll();
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_SUCCESS), any(DataCallResponse.class));
         updatePreferredNetworkType(NETWORK_TYPE_BITMASK_NR);
 
-        verify(mMockEpdgTunnelManager, never())
-                .closeTunnel(any(), anyBoolean(), any(), any(), anyInt());
+        verify(mMockEpdgTunnelManager, never()).closeTunnel(any(), anyBoolean(), any(), anyInt());
     }
 
     @Test
@@ -2341,18 +2303,18 @@ public class IwlanDataServiceTest {
                 IwlanCarrierConfig.KEY_UPDATE_N1_MODE_ON_UI_CHANGE_BOOL, true);
 
         mockSetupDataCallWithPduSessionId(1);
+        stubMockOnOpenedMetrics();
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties);
+                .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties, mMockOnOpenedMetrics);
         mTestLooper.dispatchAll();
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_SUCCESS), any(DataCallResponse.class));
 
         ArgumentCaptor<TunnelSetupRequest> tunnelSetupRequestCaptor =
                 ArgumentCaptor.forClass(TunnelSetupRequest.class);
-        verify(mMockEpdgTunnelManager, times(1))
-                .bringUpTunnel(tunnelSetupRequestCaptor.capture(), any(), any());
+        verify(mMockEpdgTunnelManager).bringUpTunnel(tunnelSetupRequestCaptor.capture(), any());
         TunnelSetupRequest tunnelSetupRequest = tunnelSetupRequestCaptor.getValue();
         assertEquals(PDU_SESSION_ID_UNSET, tunnelSetupRequest.getPduSessionId());
     }
@@ -2364,33 +2326,33 @@ public class IwlanDataServiceTest {
                 IwlanCarrierConfig.KEY_UPDATE_N1_MODE_ON_UI_CHANGE_BOOL, true);
 
         mockSetupDataCallWithPduSessionId(0);
+        stubMockOnOpenedMetrics();
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties);
+                .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties, mMockOnOpenedMetrics);
         mTestLooper.dispatchAll();
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_SUCCESS), any(DataCallResponse.class));
 
         ArgumentCaptor<TunnelSetupRequest> tunnelSetupRequestCaptor =
                 ArgumentCaptor.forClass(TunnelSetupRequest.class);
-        verify(mMockEpdgTunnelManager, times(1))
-                .bringUpTunnel(tunnelSetupRequestCaptor.capture(), any(), any());
+        verify(mMockEpdgTunnelManager).bringUpTunnel(tunnelSetupRequestCaptor.capture(), any());
         TunnelSetupRequest tunnelSetupRequest = tunnelSetupRequestCaptor.getValue();
         assertEquals(PDU_SESSION_ID_UNSET, tunnelSetupRequest.getPduSessionId());
 
         updatePreferredNetworkType(NETWORK_TYPE_BITMASK_NR);
         mockSetupDataCallWithPduSessionId(1);
+        stubMockOnOpenedMetrics();
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties);
+                .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties, mMockOnOpenedMetrics);
         mTestLooper.dispatchAll();
         verify(mMockDataServiceCallback, times(2))
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_SUCCESS), any(DataCallResponse.class));
 
-        verify(mMockEpdgTunnelManager, times(1))
-                .bringUpTunnel(tunnelSetupRequestCaptor.capture(), any(), any());
+        verify(mMockEpdgTunnelManager).bringUpTunnel(tunnelSetupRequestCaptor.capture(), any());
         tunnelSetupRequest = tunnelSetupRequestCaptor.getValue();
         assertEquals(PDU_SESSION_ID_UNSET, tunnelSetupRequest.getPduSessionId());
     }
@@ -2417,11 +2379,8 @@ public class IwlanDataServiceTest {
                 mMockDataServiceCallback);
         mTestLooper.dispatchAll();
 
-        verify(mMockEpdgTunnelManager, times(1))
-                .bringUpTunnel(
-                        any(TunnelSetupRequest.class),
-                        any(IwlanTunnelCallback.class),
-                        any(IwlanTunnelMetricsImpl.class));
+        verify(mMockEpdgTunnelManager)
+                .bringUpTunnel(any(TunnelSetupRequest.class), any(IwlanTunnelCallback.class));
     }
 
     @Test
@@ -2433,8 +2392,7 @@ public class IwlanDataServiceTest {
 
         ArgumentCaptor<TunnelSetupRequest> tunnelSetupRequestCaptor =
                 ArgumentCaptor.forClass(TunnelSetupRequest.class);
-        verify(mMockEpdgTunnelManager, times(1))
-                .bringUpTunnel(tunnelSetupRequestCaptor.capture(), any(), any());
+        verify(mMockEpdgTunnelManager).bringUpTunnel(tunnelSetupRequestCaptor.capture(), any());
         TunnelSetupRequest tunnelSetupRequest = tunnelSetupRequestCaptor.getValue();
         assertEquals(pduSessionId, tunnelSetupRequest.getPduSessionId());
     }
@@ -2449,8 +2407,7 @@ public class IwlanDataServiceTest {
 
         ArgumentCaptor<TunnelSetupRequest> tunnelSetupRequestCaptor =
                 ArgumentCaptor.forClass(TunnelSetupRequest.class);
-        verify(mMockEpdgTunnelManager, times(1))
-                .bringUpTunnel(tunnelSetupRequestCaptor.capture(), any(), any());
+        verify(mMockEpdgTunnelManager).bringUpTunnel(tunnelSetupRequestCaptor.capture(), any());
         TunnelSetupRequest tunnelSetupRequest = tunnelSetupRequestCaptor.getValue();
         assertEquals(PDU_SESSION_ID_UNSET, tunnelSetupRequest.getPduSessionId());
     }
@@ -2474,9 +2431,13 @@ public class IwlanDataServiceTest {
     private void verifySetupDataCallSuccess(DataProfile dp) {
         verifySetupDataCallRequestHandled(5 /* pduSessionId */, dp);
 
+        stubMockOnOpenedMetrics();
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onOpened(dp.getApnSetting().getApnName(), mMockTunnelLinkProperties);
+                .onOpened(
+                        dp.getApnSetting().getApnName(),
+                        mMockTunnelLinkProperties,
+                        mMockOnOpenedMetrics);
         mTestLooper.dispatchAll();
     }
 
@@ -2574,7 +2535,7 @@ public class IwlanDataServiceTest {
         mSpyIwlanDataServiceProvider.requestDataCallList(mMockDataServiceCallback);
         mTestLooper.dispatchAll();
 
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onRequestDataCallListComplete(
                         eq(DataServiceCallback.RESULT_SUCCESS), dataCallListCaptor.capture());
 
@@ -2614,11 +2575,7 @@ public class IwlanDataServiceTest {
         /* Check closeTunnel() is not called. */
         verify(mMockEpdgTunnelManager, never())
                 .closeTunnel(
-                        eq(TEST_APN_NAME),
-                        anyBoolean(),
-                        any(IwlanTunnelCallback.class),
-                        any(IwlanTunnelMetricsImpl.class),
-                        anyInt());
+                        eq(TEST_APN_NAME), anyBoolean(), any(IwlanTunnelCallback.class), anyInt());
 
         mSpyIwlanDataServiceProvider.setupDataCall(
                 AccessNetworkType.IWLAN, /* AccessNetworkType */
@@ -2634,26 +2591,25 @@ public class IwlanDataServiceTest {
                 mMockDataServiceCallback);
         mTestLooper.dispatchAll();
 
-        verify(mMockEpdgTunnelManager, times(1))
+        verify(mMockEpdgTunnelManager)
                 .closeTunnel(
                         eq(TEST_APN_NAME),
                         anyBoolean(),
                         any(IwlanTunnelCallback.class),
-                        any(IwlanTunnelMetricsImpl.class),
                         eq(BRINGDOWN_REASON_SERVICE_OUT_OF_SYNC));
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_ERROR_TEMPORARILY_UNAVAILABLE), isNull());
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR));
+                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onDeactivateDataCallComplete(eq(DataServiceCallback.RESULT_SUCCESS));
         moveTimeForwardAndDispatch(3000);
 
         // No additional callbacks are involved.
-        verify(mMockDataServiceCallback, times(1)).onDeactivateDataCallComplete(anyInt());
+        verify(mMockDataServiceCallback).onDeactivateDataCallComplete(anyInt());
     }
 
     @Test
@@ -2686,17 +2642,16 @@ public class IwlanDataServiceTest {
                         eq(TEST_APN_NAME),
                         eq(true),
                         any(IwlanTunnelCallback.class),
-                        any(IwlanTunnelMetricsImpl.class),
                         eq(
                                 EpdgTunnelManager
                                         .BRINGDOWN_REASON_NETWORK_UPDATE_WHEN_TUNNEL_IN_BRINGUP));
 
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR));
+                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
 
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_SUCCESS), any(DataCallResponse.class));
         verify(mMockDataServiceCallback, never()).onDeactivateDataCallComplete(anyInt());
@@ -2737,13 +2692,13 @@ public class IwlanDataServiceTest {
 
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR));
+                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
 
         ArgumentCaptor<DataCallResponse> dataCallResponseCaptor =
                 ArgumentCaptor.forClass(DataCallResponse.class);
 
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_SUCCESS), dataCallResponseCaptor.capture());
         DataCallResponse dataCallResponse = dataCallResponseCaptor.getValue();
@@ -2785,19 +2740,73 @@ public class IwlanDataServiceTest {
 
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR));
+                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
 
         ArgumentCaptor<DataCallResponse> dataCallResponseCaptor =
                 ArgumentCaptor.forClass(DataCallResponse.class);
 
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_SUCCESS), dataCallResponseCaptor.capture());
         DataCallResponse dataCallResponse = dataCallResponseCaptor.getValue();
         assertEquals(5L, dataCallResponse.getRetryDurationMillis());
     }
 
+    @Test
+    public void testTriggerNetworkValidationByEvent_shouldTrigger_ifMakingCall() {
+        // Wifi connected
+        onSystemDefaultNetworkConnected(
+                mMockNetwork, mLinkProperties, TRANSPORT_WIFI, DEFAULT_SUB_INDEX);
+
+        mTestLooper.dispatchAll();
+        sendCallStateChangedEvent(CALL_STATE_IDLE);
+        mTestLooper.dispatchAll();
+        sendCallStateChangedEvent(CALL_STATE_OFFHOOK);
+        mTestLooper.dispatchAll();
+        sendCallStateChangedEvent(CALL_STATE_IDLE);
+        mTestLooper.dispatchAll();
+        verify(mMockEpdgTunnelManager, times(1))
+                .validateUnderlyingNetwork(
+                        eq(IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_MAKING_CALL));
+    }
+
+    @Test
+    public void testTriggerNetworkValidationByEvent_shouldNotTrigger_ifAnsweringCall() {
+        // Wifi connected
+        onSystemDefaultNetworkConnected(
+                mMockNetwork, mLinkProperties, TRANSPORT_WIFI, DEFAULT_SUB_INDEX);
+
+        mTestLooper.dispatchAll();
+        sendCallStateChangedEvent(CALL_STATE_IDLE);
+        mTestLooper.dispatchAll();
+        sendCallStateChangedEvent(CALL_STATE_RINGING);
+        mTestLooper.dispatchAll();
+        sendCallStateChangedEvent(CALL_STATE_OFFHOOK);
+        mTestLooper.dispatchAll();
+        sendCallStateChangedEvent(CALL_STATE_IDLE);
+        mTestLooper.dispatchAll();
+        verify(mMockEpdgTunnelManager, never()).validateUnderlyingNetwork(anyInt());
+    }
+
+    @Test
+    public void testTriggerNetworkValidationByEvent_shouldTrigger_ifScreenOn() {
+        // Wifi connected
+        onSystemDefaultNetworkConnected(
+                mMockNetwork, mLinkProperties, TRANSPORT_WIFI, DEFAULT_SUB_INDEX);
+
+        mIwlanDataService
+                .mHandler
+                .obtainMessage(
+                        IwlanEventListener.SCREEN_ON_EVENT, DEFAULT_SLOT_INDEX, 0 /* unused */)
+                .sendToTarget();
+        mTestLooper.dispatchAll();
+
+        verify(mMockEpdgTunnelManager, times(1))
+                .validateUnderlyingNetwork(
+                        eq(IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_SCREEN_ON));
+    }
+
     @Test
     public void testEmergencyRetryTimerWithNoHandover() {
         // Wifi connected
@@ -2833,13 +2842,13 @@ public class IwlanDataServiceTest {
 
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
-                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR));
+                .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
 
         ArgumentCaptor<DataCallResponse> dataCallResponseCaptor =
                 ArgumentCaptor.forClass(DataCallResponse.class);
 
-        verify(mMockDataServiceCallback, times(1))
+        verify(mMockDataServiceCallback)
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_SUCCESS), dataCallResponseCaptor.capture());
         DataCallResponse dataCallResponse = dataCallResponseCaptor.getValue();
@@ -2847,4 +2856,12 @@ public class IwlanDataServiceTest {
                 DataCallResponse.RETRY_DURATION_UNDEFINED,
                 dataCallResponse.getRetryDurationMillis());
     }
+
+    private void stubMockOnOpenedMetrics() {
+        when(mMockOnOpenedMetrics.getApnName()).thenReturn(TEST_APN_NAME);
+        when(mMockOnOpenedMetrics.getEpdgServerAddress()).thenReturn(IP_ADDRESS);
+        when(mMockOnOpenedMetrics.getEpdgServerSelectionDuration()).thenReturn(200);
+        when(mMockOnOpenedMetrics.getIkeTunnelEstablishmentDuration()).thenReturn(1000);
+        when(mMockOnOpenedMetrics.isNetworkValidated()).thenReturn(true);
+    }
 }
diff --git a/test/com/google/android/iwlan/IwlanEventListenerTest.java b/test/com/google/android/iwlan/IwlanEventListenerTest.java
index b23ea40..b63f1fb 100644
--- a/test/com/google/android/iwlan/IwlanEventListenerTest.java
+++ b/test/com/google/android/iwlan/IwlanEventListenerTest.java
@@ -24,13 +24,13 @@ import static org.mockito.Mockito.eq;
 import static org.mockito.Mockito.lenient;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.spy;
-import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
 import android.annotation.SuppressLint;
 import android.content.ContentResolver;
 import android.content.Context;
+import android.content.Intent;
 import android.net.Uri;
 import android.net.wifi.WifiInfo;
 import android.net.wifi.WifiManager;
@@ -149,11 +149,11 @@ public class IwlanEventListenerTest {
         // First Wifi connected should not trigger WIFI_AP_CHANGED_EVENT
         when(mMockWifiInfo.getSSID()).thenReturn(WIFI_SSID_1);
         IwlanEventListener.onWifiConnected(mMockWifiInfo);
-        verify(mMockMessage, times(0)).sendToTarget();
+        verify(mMockMessage, never()).sendToTarget();
 
         when(mMockWifiInfo.getSSID()).thenReturn(WIFI_SSID_2);
         IwlanEventListener.onWifiConnected(mMockWifiInfo);
-        verify(mMockMessage, times(1)).sendToTarget();
+        verify(mMockMessage).sendToTarget();
     }
 
     @Test
@@ -177,7 +177,7 @@ public class IwlanEventListenerTest {
 
         // Trigger CROSS_SIM_CALLING_ENABLE_EVENT when cross sim calling setting is enabled
         mIwlanEventListener.notifyCurrentSetting(CROSS_SIM_URI);
-        verify(mMockMessage, times(1)).sendToTarget();
+        verify(mMockMessage).sendToTarget();
     }
 
     @Test
@@ -201,7 +201,7 @@ public class IwlanEventListenerTest {
 
         // Trigger CROSS_SIM_CALLING_DISABLE_EVENT when cross sim calling setting is disabled
         mIwlanEventListener.notifyCurrentSetting(CROSS_SIM_URI);
-        verify(mMockMessage, times(1)).sendToTarget();
+        verify(mMockMessage).sendToTarget();
     }
 
     @Test
@@ -226,7 +226,7 @@ public class IwlanEventListenerTest {
         IwlanEventListener.onCarrierConfigChanged(
                 mMockContext, DEFAULT_SLOT_INDEX, DEFAULT_SUB_ID, DEFAULT_CARRIER_INDEX);
 
-        verify(mMockMessage, times(1)).sendToTarget();
+        verify(mMockMessage).sendToTarget();
 
         // onCarrierConfigChanged with invalid Carrier id
         IwlanEventListener.onCarrierConfigChanged(
@@ -235,7 +235,7 @@ public class IwlanEventListenerTest {
                 DEFAULT_SUB_ID,
                 TelephonyManager.UNKNOWN_CARRIER_ID);
 
-        verify(mMockMessage_2, times(1)).sendToTarget();
+        verify(mMockMessage_2).sendToTarget();
     }
 
     @Test
@@ -258,10 +258,10 @@ public class IwlanEventListenerTest {
         mIwlanEventListener.setWfcEnabledUri(WFC_ENABLED_URI);
 
         mIwlanEventListener.notifyCurrentSetting(WFC_ENABLED_URI);
-        verify(mMockMessage, times(1)).sendToTarget();
+        verify(mMockMessage).sendToTarget();
 
         mIwlanEventListener.notifyCurrentSetting(WFC_ENABLED_URI);
-        verify(mMockMessage_2, times(1)).sendToTarget();
+        verify(mMockMessage_2).sendToTarget();
     }
 
     @Test
@@ -288,7 +288,7 @@ public class IwlanEventListenerTest {
                 mIwlanEventListener.getTelephonyCallback();
         mTelephonyCallback.onCellInfoChanged(arrayCi);
 
-        verify(mMockMessage, times(1)).sendToTarget();
+        verify(mMockMessage).sendToTarget();
     }
 
     @Test
@@ -309,7 +309,7 @@ public class IwlanEventListenerTest {
                 mIwlanEventListener.getTelephonyCallback();
         mTelephonyCallback.onCallStateChanged(TelephonyManager.CALL_STATE_OFFHOOK);
 
-        verify(mMockMessage, times(1)).sendToTarget();
+        verify(mMockMessage).sendToTarget();
     }
 
     @Test
@@ -340,7 +340,7 @@ public class IwlanEventListenerTest {
                 mIwlanEventListener.getTelephonyCallback();
         mTelephonyCallback.onCallStateChanged(TelephonyManager.CALL_STATE_OFFHOOK);
 
-        verify(mMockMessage, times(1)).sendToTarget();
+        verify(mMockMessage).sendToTarget();
         verify(mMockMessage_2, never()).sendToTarget();
     }
 
@@ -362,7 +362,7 @@ public class IwlanEventListenerTest {
                 .isVoWiFiSettingEnabled();
 
         mIwlanEventListener.notifyCurrentSetting(WFC_ENABLED_URI);
-        verify(mMockMessage, times(1)).sendToTarget();
+        verify(mMockMessage).sendToTarget();
     }
 
     @SuppressLint("MissingPermission")
@@ -385,7 +385,7 @@ public class IwlanEventListenerTest {
         mTelephonyCallback.onAllowedNetworkTypesChanged(
                 TelephonyManager.ALLOWED_NETWORK_TYPES_REASON_USER,
                 TelephonyManager.NETWORK_TYPE_BITMASK_LTE);
-        verify(mMockMessage, times(1)).sendToTarget();
+        verify(mMockMessage).sendToTarget();
     }
 
     @SuppressLint("MissingPermission")
@@ -408,6 +408,25 @@ public class IwlanEventListenerTest {
         mTelephonyCallback.onAllowedNetworkTypesChanged(
                 TelephonyManager.ALLOWED_NETWORK_TYPES_REASON_USER,
                 TelephonyManager.NETWORK_TYPE_BITMASK_NR);
-        verify(mMockMessage, times(1)).sendToTarget();
+        verify(mMockMessage).sendToTarget();
+    }
+
+    @SuppressLint("MissingPermission")
+    @Test
+    public void testScreenOn_shouldSendToListener() throws Exception {
+        when(mMockHandler.obtainMessage(
+                        eq(IwlanEventListener.SCREEN_ON_EVENT), eq(DEFAULT_SLOT_INDEX), anyInt()))
+                .thenReturn(mMockMessage);
+
+        events = new ArrayList<>();
+        events.add(IwlanEventListener.SCREEN_ON_EVENT);
+        mIwlanEventListener.addEventListener(events, mMockHandler);
+        IwlanEventListener.onBroadcastReceived(new Intent(Intent.ACTION_SCREEN_ON));
+
+        doThrow(new IllegalArgumentException("IllegalArgumentException at isVoWiFiSettingEnabled"))
+                .when(mMockImsMmTelManager)
+                .isVoWiFiSettingEnabled();
+
+        verify(mMockMessage).sendToTarget();
     }
 }
diff --git a/test/com/google/android/iwlan/epdg/EpdgSelectorTest.java b/test/com/google/android/iwlan/epdg/EpdgSelectorTest.java
index 7baa0fa..9f913f5 100644
--- a/test/com/google/android/iwlan/epdg/EpdgSelectorTest.java
+++ b/test/com/google/android/iwlan/epdg/EpdgSelectorTest.java
@@ -23,9 +23,7 @@ import static com.android.dx.mockito.inline.extended.ExtendedMockito.mockitoSess
 
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
-import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertThrows;
-import static org.junit.Assert.assertTrue;
 import static org.mockito.Mockito.any;
 import static org.mockito.Mockito.anyInt;
 import static org.mockito.Mockito.anyString;
@@ -39,10 +37,17 @@ import static org.mockito.Mockito.when;
 import static java.util.stream.Collectors.toList;
 
 import android.content.Context;
+import android.content.Intent;
 import android.content.SharedPreferences;
+import android.net.ConnectivityManager;
 import android.net.DnsResolver;
 import android.net.InetAddresses;
+import android.net.LinkAddress;
+import android.net.LinkProperties;
 import android.net.Network;
+import android.net.ipsec.ike.exceptions.IkeIOException;
+import android.net.ipsec.ike.exceptions.IkeNetworkLostException;
+import android.net.ipsec.ike.exceptions.IkeProtocolException;
 import android.os.Handler;
 import android.os.Looper;
 import android.telephony.CarrierConfigManager;
@@ -50,7 +55,6 @@ import android.telephony.CellIdentityGsm;
 import android.telephony.CellIdentityLte;
 import android.telephony.CellIdentityNr;
 import android.telephony.CellIdentityWcdma;
-import android.telephony.CellInfo;
 import android.telephony.CellInfoGsm;
 import android.telephony.CellInfoLte;
 import android.telephony.CellInfoNr;
@@ -59,8 +63,11 @@ import android.telephony.DataFailCause;
 import android.telephony.SubscriptionInfo;
 import android.telephony.SubscriptionManager;
 import android.telephony.TelephonyManager;
+import android.telephony.data.ApnSetting;
 import android.util.Log;
 
+import libcore.net.InetAddressUtils;
+
 import com.google.android.iwlan.ErrorPolicyManager;
 import com.google.android.iwlan.IwlanCarrierConfig;
 import com.google.android.iwlan.IwlanError;
@@ -69,6 +76,8 @@ import com.google.android.iwlan.flags.FeatureFlags;
 import org.junit.After;
 import org.junit.Before;
 import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
 import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 import org.mockito.MockitoSession;
@@ -79,12 +88,16 @@ import java.net.InetAddress;
 import java.net.UnknownHostException;
 import java.util.ArrayList;
 import java.util.Arrays;
+import java.util.Collection;
+import java.util.HashSet;
 import java.util.List;
 import java.util.concurrent.CountDownLatch;
 import java.util.concurrent.Executor;
 import java.util.concurrent.RejectedExecutionException;
 import java.util.concurrent.TimeUnit;
+import java.util.stream.Collectors;
 
+@RunWith(JUnit4.class)
 public class EpdgSelectorTest {
 
     private static final String TAG = "EpdgSelectorTest";
@@ -98,22 +111,27 @@ public class EpdgSelectorTest {
         0x38, 0x01, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x01
     };
-    private static final String TEST_IP_ADDRESS = "127.0.0.1";
-    private static final String TEST_IP_ADDRESS_1 = "127.0.0.2";
-    private static final String TEST_IP_ADDRESS_2 = "127.0.0.3";
-    private static final String TEST_IP_ADDRESS_3 = "127.0.0.4";
-    private static final String TEST_IP_ADDRESS_4 = "127.0.0.5";
-    private static final String TEST_IP_ADDRESS_5 = "127.0.0.6";
-    private static final String TEST_IP_ADDRESS_6 = "127.0.0.7";
-    private static final String TEST_IP_ADDRESS_7 = "127.0.0.8";
+
+    private static final String TEST_LOCAL_IPV4_ADDRESS = "192.168.1.100";
+    private static final String TEST_LOCAL_IPV6_ADDRESS = "2001:db8::1";
+
+    private static final String TEST_IPV4_ADDRESS = "127.0.0.1";
+    private static final String TEST_IPV4_ADDRESS_1 = "127.0.0.2";
+    private static final String TEST_IPV4_ADDRESS_2 = "127.0.0.3";
+    private static final String TEST_IPV4_ADDRESS_3 = "127.0.0.4";
+    private static final String TEST_IPV4_ADDRESS_4 = "127.0.0.5";
+    private static final String TEST_IPV4_ADDRESS_5 = "127.0.0.6";
+    private static final String TEST_IPV4_ADDRESS_6 = "127.0.0.7";
+    private static final String TEST_IPV4_ADDRESS_7 = "127.0.0.8";
     private static final String TEST_IPV6_ADDRESS = "0000:0000:0000:0000:0000:0000:0000:0001";
 
+    private static final int TEST_PCO_ID_INVALID = 0xFF00;
     private static final int TEST_PCO_ID_IPV6 = 0xFF01;
     private static final int TEST_PCO_ID_IPV4 = 0xFF02;
 
-    private final String testPcoString = "testPcoData";
-    private final byte[] pcoData = testPcoString.getBytes();
-    private final List<String> ehplmnList = new ArrayList<String>();
+    private final List<String> ehplmnList = new ArrayList<>();
+
+    private final LinkProperties mTestLinkProperties = new LinkProperties();
 
     @Mock private Context mMockContext;
     @Mock private Network mMockNetwork;
@@ -121,15 +139,8 @@ public class EpdgSelectorTest {
     @Mock private SubscriptionManager mMockSubscriptionManager;
     @Mock private SubscriptionInfo mMockSubscriptionInfo;
     @Mock private TelephonyManager mMockTelephonyManager;
+    @Mock private ConnectivityManager mMockConnectivityManager;
     @Mock private SharedPreferences mMockSharedPreferences;
-    @Mock private CellInfoGsm mMockCellInfoGsm;
-    @Mock private CellIdentityGsm mMockCellIdentityGsm;
-    @Mock private CellInfoWcdma mMockCellInfoWcdma;
-    @Mock private CellIdentityWcdma mMockCellIdentityWcdma;
-    @Mock private CellInfoLte mMockCellInfoLte;
-    @Mock private CellIdentityLte mMockCellIdentityLte;
-    @Mock private CellInfoNr mMockCellInfoNr;
-    @Mock private CellIdentityNr mMockCellIdentityNr;
     @Mock private DnsResolver mMockDnsResolver;
     @Mock private FeatureFlags mfakeFeatureFlags;
 
@@ -145,12 +156,18 @@ public class EpdgSelectorTest {
                         .mockStatic(ErrorPolicyManager.class)
                         .startMocking();
 
+        // Stub the external instances before initializing EpdgSelector,
+        // as these objects will be used in the constructor.
+        when(mMockContext.getSystemService(eq(SubscriptionManager.class)))
+                .thenReturn(mMockSubscriptionManager);
+        when(mMockContext.getSystemService(eq(TelephonyManager.class)))
+                .thenReturn(mMockTelephonyManager);
+        when(mMockContext.getSystemService(eq(ConnectivityManager.class)))
+                .thenReturn(mMockConnectivityManager);
         when(ErrorPolicyManager.getInstance(mMockContext, DEFAULT_SLOT_INDEX))
                 .thenReturn(mMockErrorPolicyManager);
-        mEpdgSelector = spy(new EpdgSelector(mMockContext, DEFAULT_SLOT_INDEX, mfakeFeatureFlags));
 
-        when(mMockContext.getSystemService(eq(SubscriptionManager.class)))
-                .thenReturn(mMockSubscriptionManager);
+        mEpdgSelector = spy(new EpdgSelector(mMockContext, DEFAULT_SLOT_INDEX, mfakeFeatureFlags));
 
         when(mMockSubscriptionManager.getActiveSubscriptionInfoForSimSlotIndex(anyInt()))
                 .thenReturn(mMockSubscriptionInfo);
@@ -161,9 +178,6 @@ public class EpdgSelectorTest {
 
         when(mMockTelephonyManager.getNetworkOperator()).thenReturn("311120");
 
-        when(mMockContext.getSystemService(eq(TelephonyManager.class)))
-                .thenReturn(mMockTelephonyManager);
-
         when(mMockTelephonyManager.createForSubscriptionId(anyInt()))
                 .thenReturn(mMockTelephonyManager);
 
@@ -177,6 +191,11 @@ public class EpdgSelectorTest {
 
         when(mMockSharedPreferences.getString(any(), any())).thenReturn("US");
 
+        when(mMockConnectivityManager.getLinkProperties(mMockNetwork))
+                .thenReturn(mTestLinkProperties);
+
+        applyTestAddressToNetworkForFamily(EpdgSelector.PROTO_FILTER_IPV4V6);
+
         // Mock carrier configs with test bundle
         IwlanCarrierConfig.putTestConfigInt(
                 CarrierConfigManager.Iwlan.KEY_EPDG_ADDRESS_IP_TYPE_PREFERENCE_INT,
@@ -193,15 +212,28 @@ public class EpdgSelectorTest {
         mFakeDns.clearAll();
     }
 
+    private List<InetAddress> getInetAddresses(String... hostnames) {
+        return Arrays.stream(hostnames)
+                .map(
+                        hostname -> {
+                            try {
+                                return InetAddress.getAllByName(hostname);
+                            } catch (UnknownHostException e) {
+                                throw new RuntimeException(e);
+                            }
+                        })
+                .flatMap(Arrays::stream)
+                .distinct()
+                .collect(Collectors.toList());
+    }
+
     @Test
     public void testStaticMethodPass() throws Exception {
         when(DnsResolver.getInstance()).thenReturn(mMockDnsResolver);
-        doReturn(true).when(mEpdgSelector).hasIpv4Address(mMockNetwork);
-        doReturn(true).when(mEpdgSelector).hasIpv6Address(mMockNetwork);
 
         // Set DnsResolver query mock
         final String testStaticAddress = "epdg.epc.mnc088.mcc888.pub.3gppnetwork.org";
-        mFakeDns.setAnswer(testStaticAddress, new String[] {TEST_IP_ADDRESS}, TYPE_A);
+        mFakeDns.setAnswer(testStaticAddress, new String[] {TEST_IPV4_ADDRESS}, TYPE_A);
 
         // Set carrier config mock
         IwlanCarrierConfig.putTestConfigIntArray(
@@ -210,13 +242,9 @@ public class EpdgSelectorTest {
         IwlanCarrierConfig.putTestConfigString(
                 CarrierConfigManager.Iwlan.KEY_EPDG_STATIC_ADDRESS_STRING, testStaticAddress);
 
-        ArrayList<InetAddress> testInetAddresses =
-                getValidatedServerListWithDefaultParams(false /*isEmergency*/);
-
-        InetAddress expectedAddress = InetAddress.getByName(TEST_IP_ADDRESS);
-
-        assertEquals(1, testInetAddresses.size());
-        assertEquals(expectedAddress, testInetAddresses.get(0));
+        var expectedAddresses = List.of(InetAddress.getAllByName(TEST_IPV4_ADDRESS));
+        var actualAddresses = getValidatedServerListWithDefaultParams(/* isEmergency= */ false);
+        assertEquals(expectedAddresses, actualAddresses);
     }
 
     @Test
@@ -226,24 +254,20 @@ public class EpdgSelectorTest {
                 new int[] {CarrierConfigManager.Iwlan.EPDG_ADDRESS_STATIC});
         // Carrier config directly contains the ePDG IP address.
         IwlanCarrierConfig.putTestConfigString(
-                CarrierConfigManager.Iwlan.KEY_EPDG_STATIC_ADDRESS_STRING, TEST_IP_ADDRESS);
+                CarrierConfigManager.Iwlan.KEY_EPDG_STATIC_ADDRESS_STRING, TEST_IPV4_ADDRESS);
 
-        ArrayList<InetAddress> testInetAddresses =
-                getValidatedServerListWithDefaultParams(false /*isEmergency*/);
-
-        assertEquals(1, testInetAddresses.size());
-        assertEquals(InetAddresses.parseNumericAddress(TEST_IP_ADDRESS), testInetAddresses.get(0));
+        var actualAddresses = getValidatedServerListWithDefaultParams(/* isEmergency= */ false);
+        assertEquals(
+                InetAddresses.parseNumericAddress(TEST_IPV4_ADDRESS), actualAddresses.getFirst());
     }
 
     @Test
     public void testRoamStaticMethodPass() throws Exception {
         when(DnsResolver.getInstance()).thenReturn(mMockDnsResolver);
-        doReturn(true).when(mEpdgSelector).hasIpv4Address(mMockNetwork);
-        doReturn(true).when(mEpdgSelector).hasIpv6Address(mMockNetwork);
 
         // Set DnsResolver query mock
         final String testRoamStaticAddress = "epdg.epc.mnc088.mcc888.pub.3gppnetwork.org";
-        mFakeDns.setAnswer(testRoamStaticAddress, new String[] {TEST_IP_ADDRESS}, TYPE_A);
+        mFakeDns.setAnswer(testRoamStaticAddress, new String[] {TEST_IPV4_ADDRESS}, TYPE_A);
 
         // Set carrier config mock
         IwlanCarrierConfig.putTestConfigIntArray(
@@ -253,13 +277,9 @@ public class EpdgSelectorTest {
                 CarrierConfigManager.Iwlan.KEY_EPDG_STATIC_ADDRESS_ROAMING_STRING,
                 testRoamStaticAddress);
 
-        ArrayList<InetAddress> testInetAddresses =
-                getValidatedServerListWithDefaultParams(false /*isEmergency*/);
-
-        InetAddress expectedAddress = InetAddress.getByName(TEST_IP_ADDRESS);
-
-        assertEquals(1, testInetAddresses.size());
-        assertEquals(expectedAddress, testInetAddresses.get(0));
+        var actualAddresses = getValidatedServerListWithDefaultParams(/* isEmergency= */ false);
+        var expectedAddresses = getInetAddresses(TEST_IPV4_ADDRESS);
+        assertEquals(expectedAddresses, actualAddresses);
     }
 
     @Test
@@ -275,28 +295,21 @@ public class EpdgSelectorTest {
     @Test
     public void testPlmnResolutionMethodWithNoPlmnInCarrierConfig() throws Exception {
         when(DnsResolver.getInstance()).thenReturn(mMockDnsResolver);
-        doReturn(true).when(mEpdgSelector).hasIpv4Address(mMockNetwork);
-        doReturn(true).when(mEpdgSelector).hasIpv6Address(mMockNetwork);
 
         // setUp() fills default values for mcc-mnc
         String expectedFqdnFromImsi = "epdg.epc.mnc120.mcc311.pub.3gppnetwork.org";
         String expectedFqdnFromEhplmn = "epdg.epc.mnc120.mcc300.pub.3gppnetwork.org";
 
-        mFakeDns.setAnswer(expectedFqdnFromImsi, new String[] {TEST_IP_ADDRESS_1}, TYPE_A);
-        mFakeDns.setAnswer(expectedFqdnFromEhplmn, new String[] {TEST_IP_ADDRESS_2}, TYPE_A);
+        mFakeDns.setAnswer(expectedFqdnFromImsi, new String[] {TEST_IPV4_ADDRESS_1}, TYPE_A);
+        mFakeDns.setAnswer(expectedFqdnFromEhplmn, new String[] {TEST_IPV4_ADDRESS_2}, TYPE_A);
 
-        ArrayList<InetAddress> testInetAddresses =
-                getValidatedServerListWithDefaultParams(false /*isEmergency*/);
-
-        assertEquals(2, testInetAddresses.size());
-        assertTrue(testInetAddresses.contains(InetAddress.getByName(TEST_IP_ADDRESS_1)));
-        assertTrue(testInetAddresses.contains(InetAddress.getByName(TEST_IP_ADDRESS_2)));
+        var actualAddresses = getValidatedServerListWithDefaultParams(/* isEmergency= */ false);
+        var expectedAddresses = getInetAddresses(TEST_IPV4_ADDRESS_1, TEST_IPV4_ADDRESS_2);
+        assertEquals(expectedAddresses, actualAddresses);
     }
 
     private void testPlmnResolutionMethod(boolean isEmergency) throws Exception {
         when(DnsResolver.getInstance()).thenReturn(mMockDnsResolver);
-        doReturn(true).when(mEpdgSelector).hasIpv4Address(mMockNetwork);
-        doReturn(true).when(mEpdgSelector).hasIpv6Address(mMockNetwork);
 
         String expectedFqdnFromImsi = "epdg.epc.mnc120.mcc311.pub.3gppnetwork.org";
         String expectedFqdnFromRplmn = "epdg.epc.mnc121.mcc311.pub.3gppnetwork.org";
@@ -312,42 +325,40 @@ public class EpdgSelectorTest {
                 CarrierConfigManager.Iwlan.KEY_MCC_MNCS_STRING_ARRAY,
                 new String[] {"310-480", "300-120", "311-120", "311-121"});
 
-        mFakeDns.setAnswer(expectedFqdnFromImsi, new String[] {TEST_IP_ADDRESS}, TYPE_A);
-        mFakeDns.setAnswer(expectedFqdnFromEhplmn, new String[] {TEST_IP_ADDRESS_1}, TYPE_A);
-        mFakeDns.setAnswer(excludedFqdnFromConfig, new String[] {TEST_IP_ADDRESS_2}, TYPE_A);
-        mFakeDns.setAnswer("sos." + expectedFqdnFromImsi, new String[] {TEST_IP_ADDRESS_3}, TYPE_A);
+        mFakeDns.setAnswer(expectedFqdnFromImsi, new String[] {TEST_IPV4_ADDRESS}, TYPE_A);
+        mFakeDns.setAnswer(expectedFqdnFromEhplmn, new String[] {TEST_IPV4_ADDRESS_1}, TYPE_A);
+        mFakeDns.setAnswer(excludedFqdnFromConfig, new String[] {TEST_IPV4_ADDRESS_2}, TYPE_A);
         mFakeDns.setAnswer(
-                "sos." + expectedFqdnFromEhplmn, new String[] {TEST_IP_ADDRESS_4}, TYPE_A);
+                "sos." + expectedFqdnFromImsi, new String[] {TEST_IPV4_ADDRESS_3}, TYPE_A);
         mFakeDns.setAnswer(
-                "sos." + excludedFqdnFromConfig, new String[] {TEST_IP_ADDRESS_5}, TYPE_A);
-        mFakeDns.setAnswer(expectedFqdnFromRplmn, new String[] {TEST_IP_ADDRESS_6}, TYPE_A);
+                "sos." + expectedFqdnFromEhplmn, new String[] {TEST_IPV4_ADDRESS_4}, TYPE_A);
         mFakeDns.setAnswer(
-                "sos." + expectedFqdnFromRplmn, new String[] {TEST_IP_ADDRESS_7}, TYPE_A);
-
-        ArrayList<InetAddress> testInetAddresses =
-                getValidatedServerListWithDefaultParams(isEmergency);
-
-        if (isEmergency) {
-            assertEquals(6, testInetAddresses.size());
-            assertEquals(InetAddress.getByName(TEST_IP_ADDRESS_7), testInetAddresses.get(0));
-            assertEquals(InetAddress.getByName(TEST_IP_ADDRESS_6), testInetAddresses.get(1));
-            assertEquals(InetAddress.getByName(TEST_IP_ADDRESS_3), testInetAddresses.get(2));
-            assertEquals(InetAddress.getByName(TEST_IP_ADDRESS), testInetAddresses.get(3));
-            assertEquals(InetAddress.getByName(TEST_IP_ADDRESS_4), testInetAddresses.get(4));
-            assertEquals(InetAddress.getByName(TEST_IP_ADDRESS_1), testInetAddresses.get(5));
-        } else {
-            assertEquals(3, testInetAddresses.size());
-            assertEquals(InetAddress.getByName(TEST_IP_ADDRESS_6), testInetAddresses.get(0));
-            assertEquals(InetAddress.getByName(TEST_IP_ADDRESS), testInetAddresses.get(1));
-            assertEquals(InetAddress.getByName(TEST_IP_ADDRESS_1), testInetAddresses.get(2));
-        }
+                "sos." + excludedFqdnFromConfig, new String[] {TEST_IPV4_ADDRESS_5}, TYPE_A);
+        mFakeDns.setAnswer(expectedFqdnFromRplmn, new String[] {TEST_IPV4_ADDRESS_6}, TYPE_A);
+        mFakeDns.setAnswer(
+                "sos." + expectedFqdnFromRplmn, new String[] {TEST_IPV4_ADDRESS_7}, TYPE_A);
+
+        var actualAddresses = getValidatedServerListWithDefaultParams(isEmergency);
+        var expectedAddresses =
+                getInetAddresses(
+                        isEmergency
+                                ? new String[] {
+                                    TEST_IPV4_ADDRESS_7,
+                                    TEST_IPV4_ADDRESS_6,
+                                    TEST_IPV4_ADDRESS_3,
+                                    TEST_IPV4_ADDRESS,
+                                    TEST_IPV4_ADDRESS_4,
+                                    TEST_IPV4_ADDRESS_1
+                                }
+                                : new String[] {
+                                    TEST_IPV4_ADDRESS_6, TEST_IPV4_ADDRESS, TEST_IPV4_ADDRESS_1
+                                });
+        assertEquals(expectedAddresses, actualAddresses);
     }
 
     @Test
     public void testPlmnResolutionMethodWithDuplicatedImsiAndEhplmn() throws Exception {
         when(DnsResolver.getInstance()).thenReturn(mMockDnsResolver);
-        doReturn(true).when(mEpdgSelector).hasIpv4Address(mMockNetwork);
-        doReturn(true).when(mEpdgSelector).hasIpv6Address(mMockNetwork);
 
         String fqdnFromEhplmn1 = "epdg.epc.mnc120.mcc300.pub.3gppnetwork.org";
         String fqdnFromEhplmn2AndImsi = "epdg.epc.mnc120.mcc311.pub.3gppnetwork.org";
@@ -368,25 +379,22 @@ public class EpdgSelectorTest {
                     CarrierConfigManager.Iwlan.EPDG_PLMN_EHPLMN_ALL,
                 });
 
-        mFakeDns.setAnswer(fqdnFromEhplmn1, new String[] {TEST_IP_ADDRESS}, TYPE_A);
-        mFakeDns.setAnswer(fqdnFromEhplmn2AndImsi, new String[] {TEST_IP_ADDRESS_1}, TYPE_A);
-        mFakeDns.setAnswer(fqdnFromEhplmn3, new String[] {TEST_IP_ADDRESS_2}, TYPE_A);
-        mFakeDns.setAnswer(fqdnFromEhplmn4, new String[] {TEST_IP_ADDRESS_3}, TYPE_A);
-
-        ArrayList<InetAddress> testInetAddresses = getValidatedServerListWithDefaultParams(false);
-
-        assertEquals(4, testInetAddresses.size());
-        assertEquals(InetAddress.getByName(TEST_IP_ADDRESS_1), testInetAddresses.get(0));
-        assertEquals(InetAddress.getByName(TEST_IP_ADDRESS), testInetAddresses.get(1));
-        assertEquals(InetAddress.getByName(TEST_IP_ADDRESS_2), testInetAddresses.get(2));
-        assertEquals(InetAddress.getByName(TEST_IP_ADDRESS_3), testInetAddresses.get(3));
+        mFakeDns.setAnswer(fqdnFromEhplmn1, new String[] {TEST_IPV4_ADDRESS}, TYPE_A);
+        mFakeDns.setAnswer(fqdnFromEhplmn2AndImsi, new String[] {TEST_IPV4_ADDRESS_1}, TYPE_A);
+        mFakeDns.setAnswer(fqdnFromEhplmn3, new String[] {TEST_IPV4_ADDRESS_2}, TYPE_A);
+        mFakeDns.setAnswer(fqdnFromEhplmn4, new String[] {TEST_IPV4_ADDRESS_3}, TYPE_A);
+
+        List<InetAddress> actualAddresses = getValidatedServerListWithDefaultParams(false);
+        String[] testIpAddresses = {
+            TEST_IPV4_ADDRESS_1, TEST_IPV4_ADDRESS, TEST_IPV4_ADDRESS_2, TEST_IPV4_ADDRESS_3,
+        };
+        List<InetAddress> expectedAddresses = getInetAddresses(testIpAddresses);
+        assertEquals(expectedAddresses, actualAddresses);
     }
 
     @Test
     public void testPlmnResolutionMethodWithInvalidLengthPlmns() throws Exception {
         when(DnsResolver.getInstance()).thenReturn(mMockDnsResolver);
-        doReturn(true).when(mEpdgSelector).hasIpv4Address(mMockNetwork);
-        doReturn(true).when(mEpdgSelector).hasIpv6Address(mMockNetwork);
 
         when(mMockSubscriptionInfo.getMccString()).thenReturn("31");
         when(mMockSubscriptionInfo.getMncString()).thenReturn("12");
@@ -406,16 +414,13 @@ public class EpdgSelectorTest {
                     CarrierConfigManager.Iwlan.EPDG_PLMN_EHPLMN_ALL,
                 });
 
-        ArrayList<InetAddress> testInetAddresses = getValidatedServerListWithDefaultParams(false);
-
-        assertEquals(0, testInetAddresses.size());
+        List<InetAddress> actualAddresses = getValidatedServerListWithDefaultParams(false);
+        assertEquals(0, actualAddresses.size());
     }
 
     @Test
     public void testPlmnResolutionMethodWithInvalidCharacterPlmns() throws Exception {
         when(DnsResolver.getInstance()).thenReturn(mMockDnsResolver);
-        doReturn(true).when(mEpdgSelector).hasIpv4Address(mMockNetwork);
-        doReturn(true).when(mEpdgSelector).hasIpv6Address(mMockNetwork);
 
         when(mMockSubscriptionInfo.getMccString()).thenReturn("a b");
         when(mMockSubscriptionInfo.getMncString()).thenReturn("!@#");
@@ -436,16 +441,13 @@ public class EpdgSelectorTest {
                     CarrierConfigManager.Iwlan.EPDG_PLMN_EHPLMN_ALL,
                 });
 
-        ArrayList<InetAddress> testInetAddresses = getValidatedServerListWithDefaultParams(false);
-
-        assertEquals(0, testInetAddresses.size());
+        List<InetAddress> actualAddresses = getValidatedServerListWithDefaultParams(false);
+        assertEquals(0, actualAddresses.size());
     }
 
     @Test
     public void testPlmnResolutionMethodWithEmptyPlmns() throws Exception {
         when(DnsResolver.getInstance()).thenReturn(mMockDnsResolver);
-        doReturn(true).when(mEpdgSelector).hasIpv4Address(mMockNetwork);
-        doReturn(true).when(mEpdgSelector).hasIpv6Address(mMockNetwork);
 
         when(mMockSubscriptionInfo.getMccString()).thenReturn(null);
         when(mMockSubscriptionInfo.getMncString()).thenReturn(null);
@@ -464,16 +466,13 @@ public class EpdgSelectorTest {
                     CarrierConfigManager.Iwlan.EPDG_PLMN_EHPLMN_ALL,
                 });
 
-        ArrayList<InetAddress> testInetAddresses = getValidatedServerListWithDefaultParams(false);
-
-        assertEquals(0, testInetAddresses.size());
+        List<InetAddress> actualAddresses = getValidatedServerListWithDefaultParams(false);
+        assertEquals(0, actualAddresses.size());
     }
 
     @Test
     public void testPlmnResolutionMethodWithFirstEhplmn() throws Exception {
         when(DnsResolver.getInstance()).thenReturn(mMockDnsResolver);
-        doReturn(true).when(mEpdgSelector).hasIpv4Address(mMockNetwork);
-        doReturn(true).when(mEpdgSelector).hasIpv6Address(mMockNetwork);
 
         String fqdnFromEhplmn1 = "epdg.epc.mnc120.mcc300.pub.3gppnetwork.org";
         String fqdnFromEhplmn2 = "epdg.epc.mnc121.mcc300.pub.3gppnetwork.org";
@@ -491,22 +490,19 @@ public class EpdgSelectorTest {
                 CarrierConfigManager.Iwlan.KEY_EPDG_PLMN_PRIORITY_INT_ARRAY,
                 new int[] {CarrierConfigManager.Iwlan.EPDG_PLMN_EHPLMN_FIRST});
 
-        mFakeDns.setAnswer(fqdnFromEhplmn1, new String[] {TEST_IP_ADDRESS}, TYPE_A);
-        mFakeDns.setAnswer(fqdnFromEhplmn2, new String[] {TEST_IP_ADDRESS_1}, TYPE_A);
-        mFakeDns.setAnswer(fqdnFromEhplmn3, new String[] {TEST_IP_ADDRESS_2}, TYPE_A);
-        mFakeDns.setAnswer(fqdnFromEhplmn4, new String[] {TEST_IP_ADDRESS_3}, TYPE_A);
+        mFakeDns.setAnswer(fqdnFromEhplmn1, new String[] {TEST_IPV4_ADDRESS}, TYPE_A);
+        mFakeDns.setAnswer(fqdnFromEhplmn2, new String[] {TEST_IPV4_ADDRESS_1}, TYPE_A);
+        mFakeDns.setAnswer(fqdnFromEhplmn3, new String[] {TEST_IPV4_ADDRESS_2}, TYPE_A);
+        mFakeDns.setAnswer(fqdnFromEhplmn4, new String[] {TEST_IPV4_ADDRESS_3}, TYPE_A);
 
-        ArrayList<InetAddress> testInetAddresses = getValidatedServerListWithDefaultParams(false);
-
-        assertEquals(1, testInetAddresses.size());
-        assertEquals(InetAddress.getByName(TEST_IP_ADDRESS), testInetAddresses.get(0));
+        var actualAddresses = getValidatedServerListWithDefaultParams(/* isEmergency= */ false);
+        var expectedAddresses = getInetAddresses(TEST_IPV4_ADDRESS);
+        assertEquals(expectedAddresses, actualAddresses);
     }
 
     @Test
     public void testPlmnResolutionMethodWithRplmn() throws Exception {
         when(DnsResolver.getInstance()).thenReturn(mMockDnsResolver);
-        doReturn(true).when(mEpdgSelector).hasIpv4Address(mMockNetwork);
-        doReturn(true).when(mEpdgSelector).hasIpv6Address(mMockNetwork);
 
         String fqdnFromRplmn = "epdg.epc.mnc122.mcc300.pub.3gppnetwork.org";
         String fqdnFromEhplmn1 = "epdg.epc.mnc120.mcc300.pub.3gppnetwork.org";
@@ -526,21 +522,18 @@ public class EpdgSelectorTest {
                 CarrierConfigManager.Iwlan.KEY_EPDG_PLMN_PRIORITY_INT_ARRAY,
                 new int[] {CarrierConfigManager.Iwlan.EPDG_PLMN_RPLMN});
 
-        mFakeDns.setAnswer(fqdnFromRplmn, new String[] {TEST_IP_ADDRESS}, TYPE_A);
-        mFakeDns.setAnswer(fqdnFromEhplmn1, new String[] {TEST_IP_ADDRESS_1}, TYPE_A);
-        mFakeDns.setAnswer(fqdnFromEhplmn2, new String[] {TEST_IP_ADDRESS_2}, TYPE_A);
-
-        ArrayList<InetAddress> testInetAddresses = getValidatedServerListWithDefaultParams(false);
+        mFakeDns.setAnswer(fqdnFromRplmn, new String[] {TEST_IPV4_ADDRESS}, TYPE_A);
+        mFakeDns.setAnswer(fqdnFromEhplmn1, new String[] {TEST_IPV4_ADDRESS_1}, TYPE_A);
+        mFakeDns.setAnswer(fqdnFromEhplmn2, new String[] {TEST_IPV4_ADDRESS_2}, TYPE_A);
 
-        assertEquals(1, testInetAddresses.size());
-        assertEquals(InetAddress.getByName(TEST_IP_ADDRESS), testInetAddresses.get(0));
+        var actualAddresses = getValidatedServerListWithDefaultParams(/* isEmergency= */ false);
+        var expectedAddresses = getInetAddresses(TEST_IPV4_ADDRESS);
+        assertEquals(expectedAddresses, actualAddresses);
     }
 
     @Test
     public void testCarrierConfigStaticAddressList() throws Exception {
         when(DnsResolver.getInstance()).thenReturn(mMockDnsResolver);
-        doReturn(true).when(mEpdgSelector).hasIpv4Address(mMockNetwork);
-        doReturn(true).when(mEpdgSelector).hasIpv6Address(mMockNetwork);
 
         // Set DnsResolver query mock
         final String addr1 = "epdg.epc.mnc480.mcc310.pub.3gppnetwork.org";
@@ -548,9 +541,9 @@ public class EpdgSelectorTest {
         final String addr3 = "epdg.epc.mnc120.mcc311.pub.3gppnetwork.org";
         final String testStaticAddress = addr1 + "," + addr2 + "," + addr3;
 
-        mFakeDns.setAnswer(addr1, new String[] {TEST_IP_ADDRESS_1}, TYPE_A);
-        mFakeDns.setAnswer(addr2, new String[] {TEST_IP_ADDRESS_2}, TYPE_A);
-        mFakeDns.setAnswer(addr3, new String[] {TEST_IP_ADDRESS}, TYPE_A);
+        mFakeDns.setAnswer(addr1, new String[] {TEST_IPV4_ADDRESS_1}, TYPE_A);
+        mFakeDns.setAnswer(addr2, new String[] {TEST_IPV4_ADDRESS_2}, TYPE_A);
+        mFakeDns.setAnswer(addr3, new String[] {TEST_IPV4_ADDRESS}, TYPE_A);
 
         // Set carrier config mock
         IwlanCarrierConfig.putTestConfigIntArray(
@@ -559,34 +552,31 @@ public class EpdgSelectorTest {
         IwlanCarrierConfig.putTestConfigString(
                 CarrierConfigManager.Iwlan.KEY_EPDG_STATIC_ADDRESS_STRING, testStaticAddress);
 
-        ArrayList<InetAddress> testInetAddresses =
-                getValidatedServerListWithDefaultParams(false /*isEmergency*/);
-
-        assertEquals(3, testInetAddresses.size());
-        assertEquals(InetAddress.getByName(TEST_IP_ADDRESS_1), testInetAddresses.get(0));
-        assertEquals(InetAddress.getByName(TEST_IP_ADDRESS_2), testInetAddresses.get(1));
-        assertEquals(InetAddress.getByName(TEST_IP_ADDRESS), testInetAddresses.get(2));
+        var actualAddresses = getValidatedServerListWithDefaultParams(/* isEmergency= */ false);
+        var expectedAddresses =
+                getInetAddresses(TEST_IPV4_ADDRESS_1, TEST_IPV4_ADDRESS_2, TEST_IPV4_ADDRESS);
+        assertEquals(expectedAddresses, actualAddresses);
     }
 
-    private ArrayList<InetAddress> getValidatedServerListWithDefaultParams(boolean isEmergency)
+    private List<InetAddress> getValidatedServerListWithDefaultParams(boolean isEmergency)
             throws Exception {
         return getValidatedServerListWithIpPreference(
                 EpdgSelector.PROTO_FILTER_IPV4V6, EpdgSelector.IPV4_PREFERRED, isEmergency);
     }
 
-    private ArrayList<InetAddress> getValidatedServerListWithIpPreference(
+    private List<InetAddress> getValidatedServerListWithIpPreference(
             @EpdgSelector.ProtoFilter int filter,
             @EpdgSelector.EpdgAddressOrder int order,
             boolean isEmergency)
             throws Exception {
-        ArrayList<InetAddress> testInetAddresses = new ArrayList<InetAddress>();
+        List<InetAddress> actualAddresses = new ArrayList<>();
         final CountDownLatch latch = new CountDownLatch(1);
         IwlanError ret =
                 mEpdgSelector.getValidatedServerList(
-                        1234,
+                        /* transactionId= */ 1234,
                         filter,
                         order,
-                        false /* isRoaming */,
+                        /* isRoaming= */ false,
                         isEmergency,
                         mMockNetwork,
                         new EpdgSelector.EpdgSelectorCallback() {
@@ -595,9 +585,7 @@ public class EpdgSelectorTest {
                                     int transactionId, List<InetAddress> validIPList) {
                                 assertEquals(1234, transactionId);
 
-                                for (InetAddress mInetAddress : validIPList) {
-                                    testInetAddresses.add(mInetAddress);
-                                }
+                                actualAddresses.addAll(validIPList);
                                 Log.d(TAG, "onServerListChanged received");
                                 latch.countDown();
                             }
@@ -611,76 +599,38 @@ public class EpdgSelectorTest {
 
         assertEquals(IwlanError.NO_ERROR, ret.getErrorType());
         latch.await(1, TimeUnit.SECONDS);
-        return testInetAddresses;
-    }
-
-    @Test
-    public void testSetPcoData() throws Exception {
-        addTestPcoIdsToTestConfigBundle();
-
-        boolean retIPv6 = mEpdgSelector.setPcoData(TEST_PCO_ID_IPV6, pcoData);
-        boolean retIPv4 = mEpdgSelector.setPcoData(TEST_PCO_ID_IPV4, pcoData);
-        boolean retIncorrect = mEpdgSelector.setPcoData(0xFF00, pcoData);
-
-        assertTrue(retIPv6);
-        assertTrue(retIPv4);
-        assertFalse(retIncorrect);
+        return actualAddresses;
     }
 
     @Test
-    public void testPcoResolutionMethod() throws Exception {
-        IwlanCarrierConfig.putTestConfigIntArray(
-                CarrierConfigManager.Iwlan.KEY_EPDG_ADDRESS_PRIORITY_INT_ARRAY,
-                new int[] {CarrierConfigManager.Iwlan.EPDG_ADDRESS_PCO});
+    public void testResolutionMethodPco_noPcoData() throws Exception {
         addTestPcoIdsToTestConfigBundle();
 
-        mEpdgSelector.clearPcoData();
-        assertTrue(mEpdgSelector.setPcoData(TEST_PCO_ID_IPV6, TEST_PCO_IPV6_DATA));
-        assertTrue(mEpdgSelector.setPcoData(TEST_PCO_ID_IPV4, TEST_PCO_IPV4_DATA));
+        sendCarrierSignalPcoValue(ApnSetting.TYPE_IMS, TEST_PCO_ID_IPV4, TEST_PCO_NO_DATA);
+        sendCarrierSignalPcoValue(ApnSetting.TYPE_IMS, TEST_PCO_ID_IPV6, TEST_PCO_NO_DATA);
 
-        ArrayList<InetAddress> testInetAddresses =
-                getValidatedServerListWithDefaultParams(false /* isEmergency */);
+        List<InetAddress> actualAddresses =
+                getValidatedServerListWithDefaultParams(/* isEmergency= */ false);
 
-        assertEquals(2, testInetAddresses.size());
-        assertTrue(testInetAddresses.contains(InetAddress.getByName(TEST_IP_ADDRESS)));
-        assertTrue(testInetAddresses.contains(InetAddress.getByName(TEST_IPV6_ADDRESS)));
+        assertEquals(0, actualAddresses.size());
     }
 
     @Test
-    public void testPcoResolutionMethodWithNoPcoData() throws Exception {
-        IwlanCarrierConfig.putTestConfigIntArray(
-                CarrierConfigManager.Iwlan.KEY_EPDG_ADDRESS_PRIORITY_INT_ARRAY,
-                new int[] {CarrierConfigManager.Iwlan.EPDG_ADDRESS_PCO});
+    public void testResolutionMethodPco_withPlmnData() throws Exception {
         addTestPcoIdsToTestConfigBundle();
 
-        mEpdgSelector.clearPcoData();
-        assertTrue(mEpdgSelector.setPcoData(TEST_PCO_ID_IPV6, TEST_PCO_NO_DATA));
-        assertTrue(mEpdgSelector.setPcoData(TEST_PCO_ID_IPV4, TEST_PCO_NO_DATA));
+        sendCarrierSignalPcoValue(ApnSetting.TYPE_IMS, TEST_PCO_ID_IPV4, TEST_PCO_PLMN_DATA);
+        sendCarrierSignalPcoValue(ApnSetting.TYPE_IMS, TEST_PCO_ID_IPV6, TEST_PCO_PLMN_DATA);
 
-        ArrayList<InetAddress> testInetAddresses =
-                getValidatedServerListWithDefaultParams(false /* isEmergency */);
-
-        assertEquals(0, testInetAddresses.size());
+        List<InetAddress> actualAddresses =
+                getValidatedServerListWithDefaultParams(/* isEmergency= */ false);
+        assertEquals(0, actualAddresses.size());
     }
 
-    @Test
-    public void testPcoResolutionMethodWithOnlyPlmnData() throws Exception {
+    private void addTestPcoIdsToTestConfigBundle() {
         IwlanCarrierConfig.putTestConfigIntArray(
                 CarrierConfigManager.Iwlan.KEY_EPDG_ADDRESS_PRIORITY_INT_ARRAY,
                 new int[] {CarrierConfigManager.Iwlan.EPDG_ADDRESS_PCO});
-        addTestPcoIdsToTestConfigBundle();
-
-        mEpdgSelector.clearPcoData();
-        assertTrue(mEpdgSelector.setPcoData(TEST_PCO_ID_IPV6, TEST_PCO_PLMN_DATA));
-        assertTrue(mEpdgSelector.setPcoData(TEST_PCO_ID_IPV4, TEST_PCO_PLMN_DATA));
-
-        ArrayList<InetAddress> testInetAddresses =
-                getValidatedServerListWithDefaultParams(false /* isEmergency */);
-
-        assertEquals(0, testInetAddresses.size());
-    }
-
-    private void addTestPcoIdsToTestConfigBundle() {
         IwlanCarrierConfig.putTestConfigInt(
                 CarrierConfigManager.Iwlan.KEY_EPDG_PCO_ID_IPV6_INT, TEST_PCO_ID_IPV6);
         IwlanCarrierConfig.putTestConfigInt(
@@ -700,69 +650,57 @@ public class EpdgSelectorTest {
     private void testCellularResolutionMethod(boolean isEmergency) throws Exception {
         when(DnsResolver.getInstance()).thenReturn(mMockDnsResolver);
 
-        int testMcc = 311;
-        int testMnc = 120;
-        String testMccString = "311";
-        String testMncString = "120";
-        int testLac = 65484;
-        int testTac = 65484;
-        int testNrTac = 16764074;
-
-        List<CellInfo> fakeCellInfoArray = new ArrayList<CellInfo>();
+        var mockCellInfoGsm = mock(CellInfoGsm.class);
+        var mockCellIdentityGsm = mock(CellIdentityGsm.class);
+        var mockCellInfoWcdma = mock(CellInfoWcdma.class);
+        var mockCellIdentityWcdma = mock(CellIdentityWcdma.class);
+        var mockCellInfoLte = mock(CellInfoLte.class);
+        var mockCellIdentityLte = mock(CellIdentityLte.class);
+        var mockCellInfoNr = mock(CellInfoNr.class);
+        var mockCellIdentityNr = mock(CellIdentityNr.class);
+        var testLac = 65484;
+        var testTac = 65484;
+        var testNrTac = 16764074;
+        var fakeCellInfoArray =
+                List.of(mockCellInfoGsm, mockCellInfoWcdma, mockCellInfoLte, mockCellInfoNr);
 
         IwlanCarrierConfig.putTestConfigIntArray(
                 CarrierConfigManager.Iwlan.KEY_EPDG_ADDRESS_PRIORITY_INT_ARRAY,
                 new int[] {CarrierConfigManager.Iwlan.EPDG_ADDRESS_CELLULAR_LOC});
 
         // Set cell info mock
-        fakeCellInfoArray.add(mMockCellInfoGsm);
-        when(mMockCellInfoGsm.isRegistered()).thenReturn(true);
-        when(mMockCellInfoGsm.getCellIdentity()).thenReturn(mMockCellIdentityGsm);
-        when(mMockCellIdentityGsm.getMcc()).thenReturn(testMcc);
-        when(mMockCellIdentityGsm.getMnc()).thenReturn(testMnc);
-        when(mMockCellIdentityGsm.getLac()).thenReturn(testLac);
-
-        fakeCellInfoArray.add(mMockCellInfoWcdma);
-        when(mMockCellInfoWcdma.isRegistered()).thenReturn(true);
-        when(mMockCellInfoWcdma.getCellIdentity()).thenReturn(mMockCellIdentityWcdma);
-        when(mMockCellIdentityWcdma.getMcc()).thenReturn(testMcc);
-        when(mMockCellIdentityWcdma.getMnc()).thenReturn(testMnc);
-        when(mMockCellIdentityWcdma.getLac()).thenReturn(testLac);
-
-        fakeCellInfoArray.add(mMockCellInfoLte);
-        when(mMockCellInfoLte.isRegistered()).thenReturn(true);
-        when(mMockCellInfoLte.getCellIdentity()).thenReturn(mMockCellIdentityLte);
-        when(mMockCellIdentityLte.getMcc()).thenReturn(testMcc);
-        when(mMockCellIdentityLte.getMnc()).thenReturn(testMnc);
-        when(mMockCellIdentityLte.getTac()).thenReturn(testTac);
-
-        fakeCellInfoArray.add(mMockCellInfoNr);
-        when(mMockCellInfoNr.isRegistered()).thenReturn(true);
-        when(mMockCellInfoNr.getCellIdentity()).thenReturn(mMockCellIdentityNr);
-        when(mMockCellIdentityNr.getMccString()).thenReturn(testMccString);
-        when(mMockCellIdentityNr.getMncString()).thenReturn(testMncString);
-        when(mMockCellIdentityNr.getTac()).thenReturn(testNrTac);
+        when(mockCellInfoGsm.isRegistered()).thenReturn(true);
+        when(mockCellInfoGsm.getCellIdentity()).thenReturn(mockCellIdentityGsm);
+        when(mockCellIdentityGsm.getLac()).thenReturn(testLac);
+
+        when(mockCellInfoWcdma.isRegistered()).thenReturn(true);
+        when(mockCellInfoWcdma.getCellIdentity()).thenReturn(mockCellIdentityWcdma);
+        when(mockCellIdentityWcdma.getLac()).thenReturn(testLac);
+
+        when(mockCellInfoLte.isRegistered()).thenReturn(true);
+        when(mockCellInfoLte.getCellIdentity()).thenReturn(mockCellIdentityLte);
+        when(mockCellIdentityLte.getTac()).thenReturn(testTac);
+
+        when(mockCellInfoNr.isRegistered()).thenReturn(true);
+        when(mockCellInfoNr.getCellIdentity()).thenReturn(mockCellIdentityNr);
+        when(mockCellIdentityNr.getTac()).thenReturn(testNrTac);
 
         when(mMockTelephonyManager.getAllCellInfo()).thenReturn(fakeCellInfoArray);
 
         setAnswerForCellularMethod(isEmergency, 311, 120);
         setAnswerForCellularMethod(isEmergency, 300, 120);
-
-        ArrayList<InetAddress> testInetAddresses =
-                getValidatedServerListWithDefaultParams(isEmergency);
-
-        assertEquals(3, testInetAddresses.size());
-        assertEquals(InetAddress.getByName(TEST_IP_ADDRESS), testInetAddresses.get(0));
-        assertEquals(InetAddress.getByName(TEST_IP_ADDRESS_1), testInetAddresses.get(1));
-        assertEquals(InetAddress.getByName(TEST_IP_ADDRESS_2), testInetAddresses.get(2));
+        var actualAddresses = getValidatedServerListWithDefaultParams(isEmergency);
+        var expectedAddresses =
+                getInetAddresses(TEST_IPV4_ADDRESS, TEST_IPV4_ADDRESS_1, TEST_IPV4_ADDRESS_2);
+        assertEquals(expectedAddresses, actualAddresses);
     }
 
     @Test
     public void testTemporaryExcludedIpAddressWhenDisabledExcludeFailedIp() throws Exception {
         doReturn(false).when(mfakeFeatureFlags).epdgSelectionExcludeFailedIpAddress();
         when(DnsResolver.getInstance()).thenReturn(mMockDnsResolver);
-        doReturn(true).when(mEpdgSelector).hasIpv4Address(mMockNetwork);
-        doReturn(true).when(mEpdgSelector).hasIpv6Address(mMockNetwork);
+
+        final IkeIOException mockIkeIOException = mock(IkeIOException.class);
 
         String fqdnFromRplmn = "epdg.epc.mnc122.mcc300.pub.3gppnetwork.org";
         final String staticAddr = "epdg.epc.mnc120.mcc300.pub.3gppnetwork.org";
@@ -784,51 +722,36 @@ public class EpdgSelectorTest {
         IwlanCarrierConfig.putTestConfigString(
                 CarrierConfigManager.Iwlan.KEY_EPDG_STATIC_ADDRESS_STRING, staticAddr);
 
-        mFakeDns.setAnswer(fqdnFromRplmn, new String[] {TEST_IP_ADDRESS}, TYPE_A);
-        mFakeDns.setAnswer(staticAddr, new String[] {TEST_IP_ADDRESS_1, TEST_IPV6_ADDRESS}, TYPE_A);
+        mFakeDns.setAnswer(fqdnFromRplmn, new String[] {TEST_IPV4_ADDRESS}, TYPE_A);
+        mFakeDns.setAnswer(
+                staticAddr, new String[] {TEST_IPV4_ADDRESS_1, TEST_IPV6_ADDRESS}, TYPE_A);
 
-        ArrayList<InetAddress> testInetAddresses = getValidatedServerListWithDefaultParams(false);
-        assertArrayEquals(
-                List.of(
-                                InetAddress.getByName(TEST_IP_ADDRESS),
-                                InetAddress.getByName(TEST_IP_ADDRESS_1),
-                                InetAddress.getByName(TEST_IPV6_ADDRESS))
-                        .toArray(),
-                testInetAddresses.toArray());
+        var expectedAddresses =
+                getInetAddresses(TEST_IPV4_ADDRESS, TEST_IPV4_ADDRESS_1, TEST_IPV6_ADDRESS);
+        var actualAddresses = getValidatedServerListWithDefaultParams(/* isEmergency= */ false);
+        assertEquals(expectedAddresses, actualAddresses);
 
-        mEpdgSelector.onEpdgConnectionFailed(InetAddress.getByName(TEST_IP_ADDRESS));
+        mEpdgSelector.onEpdgConnectionFailed(
+                InetAddressUtils.parseNumericAddress(TEST_IPV4_ADDRESS), mockIkeIOException);
         // Flag disabled should not affect the result
-        testInetAddresses = getValidatedServerListWithDefaultParams(false);
-        assertArrayEquals(
-                List.of(
-                                InetAddress.getByName(TEST_IP_ADDRESS),
-                                InetAddress.getByName(TEST_IP_ADDRESS_1),
-                                InetAddress.getByName(TEST_IPV6_ADDRESS))
-                        .toArray(),
-                testInetAddresses.toArray());
+        assertEquals(expectedAddresses, actualAddresses);
 
         mEpdgSelector.onEpdgConnectedSuccessfully();
         // Flag disabled should not affect the result
-        testInetAddresses = getValidatedServerListWithDefaultParams(false);
-        assertArrayEquals(
-                List.of(
-                                InetAddress.getByName(TEST_IP_ADDRESS),
-                                InetAddress.getByName(TEST_IP_ADDRESS_1),
-                                InetAddress.getByName(TEST_IPV6_ADDRESS))
-                        .toArray(),
-                testInetAddresses.toArray());
+        assertEquals(expectedAddresses, actualAddresses);
     }
 
     @Test
     public void testTemporaryExcludedIpAddressWhenEnabledExcludeFailedIp() throws Exception {
         doReturn(true).when(mfakeFeatureFlags).epdgSelectionExcludeFailedIpAddress();
         when(DnsResolver.getInstance()).thenReturn(mMockDnsResolver);
-        doReturn(true).when(mEpdgSelector).hasIpv4Address(mMockNetwork);
-        doReturn(true).when(mEpdgSelector).hasIpv6Address(mMockNetwork);
 
         final String fqdnFromRplmn = "epdg.epc.mnc122.mcc300.pub.3gppnetwork.org";
         final String staticAddr = "epdg.epc.mnc120.mcc300.pub.3gppnetwork.org";
 
+        final IkeIOException mockIkeIOException = mock(IkeIOException.class);
+        final IkeProtocolException mockIkeProtocolException = mock(IkeProtocolException.class);
+
         when(mMockTelephonyManager.getNetworkOperator()).thenReturn("300122");
         IwlanCarrierConfig.putTestConfigStringArray(
                 CarrierConfigManager.Iwlan.KEY_MCC_MNCS_STRING_ARRAY, new String[] {"300-122"});
@@ -846,94 +769,77 @@ public class EpdgSelectorTest {
         IwlanCarrierConfig.putTestConfigString(
                 CarrierConfigManager.Iwlan.KEY_EPDG_STATIC_ADDRESS_STRING, staticAddr);
 
-        mFakeDns.setAnswer(fqdnFromRplmn, new String[] {TEST_IP_ADDRESS}, TYPE_A);
-        mFakeDns.setAnswer(staticAddr, new String[] {TEST_IP_ADDRESS_1, TEST_IPV6_ADDRESS}, TYPE_A);
-
-        ArrayList<InetAddress> testInetAddresses = getValidatedServerListWithDefaultParams(false);
-        assertArrayEquals(
-                List.of(
-                                InetAddress.getByName(TEST_IP_ADDRESS),
-                                InetAddress.getByName(TEST_IP_ADDRESS_1),
-                                InetAddress.getByName(TEST_IPV6_ADDRESS))
-                        .toArray(),
-                testInetAddresses.toArray());
-
-        mEpdgSelector.onEpdgConnectionFailed(InetAddress.getByName(TEST_IP_ADDRESS));
-        testInetAddresses = getValidatedServerListWithDefaultParams(false);
+        mFakeDns.setAnswer(fqdnFromRplmn, new String[] {TEST_IPV4_ADDRESS}, TYPE_A);
+        mFakeDns.setAnswer(
+                staticAddr, new String[] {TEST_IPV4_ADDRESS_1, TEST_IPV6_ADDRESS}, TYPE_A);
+
+        var actualAddresses = getValidatedServerListWithDefaultParams(/* isEmergency= */ false);
+        var expectedAddresses =
+                getInetAddresses(TEST_IPV4_ADDRESS, TEST_IPV4_ADDRESS_1, TEST_IPV6_ADDRESS);
+        assertEquals(expectedAddresses, actualAddresses);
+
+        mEpdgSelector.onEpdgConnectionFailed(
+                InetAddressUtils.parseNumericAddress(TEST_IPV4_ADDRESS), mockIkeIOException);
+        actualAddresses = getValidatedServerListWithDefaultParams(/* isEmergency= */ false);
+        expectedAddresses = getInetAddresses(TEST_IPV4_ADDRESS_1, TEST_IPV6_ADDRESS);
+        assertEquals(expectedAddresses, actualAddresses);
+
+        mEpdgSelector.onEpdgConnectionFailed(
+                InetAddress.getByName(TEST_IPV4_ADDRESS_1), mockIkeProtocolException);
+        actualAddresses = getValidatedServerListWithDefaultParams(/* isEmergency= */ false);
         assertArrayEquals(
-                List.of(
-                                InetAddress.getByName(TEST_IP_ADDRESS_1),
-                                InetAddress.getByName(TEST_IPV6_ADDRESS))
-                        .toArray(),
-                testInetAddresses.toArray());
+                List.of(InetAddress.getByName(TEST_IPV6_ADDRESS)).toArray(),
+                actualAddresses.toArray());
 
         // Reset temporary excluded ip addresses
         mEpdgSelector.onEpdgConnectedSuccessfully();
-        testInetAddresses = getValidatedServerListWithDefaultParams(false);
-        assertArrayEquals(
-                List.of(
-                                InetAddress.getByName(TEST_IP_ADDRESS),
-                                InetAddress.getByName(TEST_IP_ADDRESS_1),
-                                InetAddress.getByName(TEST_IPV6_ADDRESS))
-                        .toArray(),
-                testInetAddresses.toArray());
-
-        mEpdgSelector.onEpdgConnectionFailed(InetAddress.getByName(TEST_IP_ADDRESS));
-        testInetAddresses = getValidatedServerListWithDefaultParams(false);
-        assertArrayEquals(
-                List.of(
-                                InetAddress.getByName(TEST_IP_ADDRESS_1),
-                                InetAddress.getByName(TEST_IPV6_ADDRESS))
-                        .toArray(),
-                testInetAddresses.toArray());
-
-        mEpdgSelector.onEpdgConnectionFailed(InetAddress.getByName(TEST_IPV6_ADDRESS));
-        testInetAddresses = getValidatedServerListWithDefaultParams(false);
-        assertArrayEquals(
-                List.of(InetAddress.getByName(TEST_IP_ADDRESS_1)).toArray(),
-                testInetAddresses.toArray());
-
-        mEpdgSelector.onEpdgConnectionFailed(InetAddress.getByName(TEST_IP_ADDRESS_1));
+        actualAddresses = getValidatedServerListWithDefaultParams(/* isEmergency= */ false);
+        expectedAddresses =
+                getInetAddresses(TEST_IPV4_ADDRESS, TEST_IPV4_ADDRESS_1, TEST_IPV6_ADDRESS);
+        assertEquals(expectedAddresses, actualAddresses);
+
+        mEpdgSelector.onEpdgConnectionFailed(
+                InetAddressUtils.parseNumericAddress(TEST_IPV4_ADDRESS), mockIkeProtocolException);
+        actualAddresses = getValidatedServerListWithDefaultParams(/* isEmergency= */ false);
+        expectedAddresses = getInetAddresses(TEST_IPV4_ADDRESS_1, TEST_IPV6_ADDRESS);
+        assertEquals(expectedAddresses, actualAddresses);
+
+        mEpdgSelector.onEpdgConnectionFailed(
+                InetAddress.getByName(TEST_IPV6_ADDRESS), mockIkeIOException);
+        actualAddresses = getValidatedServerListWithDefaultParams(/* isEmergency= */ false);
+        expectedAddresses = getInetAddresses(TEST_IPV4_ADDRESS_1);
+        assertEquals(expectedAddresses, actualAddresses);
+
+        mEpdgSelector.onEpdgConnectionFailed(
+                InetAddress.getByName(TEST_IPV4_ADDRESS_1), mockIkeIOException);
         // All ip addresses removed, should reset excluded address
-        testInetAddresses = getValidatedServerListWithDefaultParams(false);
-        assertArrayEquals(
-                List.of(
-                                InetAddress.getByName(TEST_IP_ADDRESS),
-                                InetAddress.getByName(TEST_IP_ADDRESS_1),
-                                InetAddress.getByName(TEST_IPV6_ADDRESS))
-                        .toArray(),
-                testInetAddresses.toArray());
-
-        mEpdgSelector.onEpdgConnectionFailed(InetAddress.getByName(TEST_IP_ADDRESS_1));
-        testInetAddresses = getValidatedServerListWithDefaultParams(false);
-        assertArrayEquals(
-                List.of(
-                                InetAddress.getByName(TEST_IP_ADDRESS),
-                                InetAddress.getByName(TEST_IPV6_ADDRESS))
-                        .toArray(),
-                testInetAddresses.toArray());
+        actualAddresses = getValidatedServerListWithDefaultParams(/* isEmergency= */ false);
+        expectedAddresses =
+                getInetAddresses(TEST_IPV4_ADDRESS, TEST_IPV4_ADDRESS_1, TEST_IPV6_ADDRESS);
+        assertEquals(expectedAddresses, actualAddresses);
 
-        // When the original result changed
-        mFakeDns.setAnswer(staticAddr, new String[] {TEST_IP_ADDRESS_1}, TYPE_A);
-        mFakeDns.setAnswer(fqdnFromRplmn, new String[] {TEST_IP_ADDRESS_3}, TYPE_A);
-        testInetAddresses = getValidatedServerListWithDefaultParams(false);
-        assertArrayEquals(
-                List.of(InetAddress.getByName(TEST_IP_ADDRESS_3)).toArray(),
-                testInetAddresses.toArray());
+        mEpdgSelector.onEpdgConnectionFailed(
+                InetAddress.getByName(TEST_IPV4_ADDRESS_1), mockIkeIOException);
+        actualAddresses = getValidatedServerListWithDefaultParams(/* isEmergency= */ false);
+        expectedAddresses = getInetAddresses(TEST_IPV4_ADDRESS, TEST_IPV6_ADDRESS);
+        assertEquals(expectedAddresses, actualAddresses);
 
-        mEpdgSelector.onEpdgConnectionFailed(InetAddress.getByName(TEST_IP_ADDRESS_3));
+        // When the original result changed
+        mFakeDns.setAnswer(staticAddr, new String[] {TEST_IPV4_ADDRESS_1}, TYPE_A);
+        mFakeDns.setAnswer(fqdnFromRplmn, new String[] {TEST_IPV4_ADDRESS_3}, TYPE_A);
+        actualAddresses = getValidatedServerListWithDefaultParams(/* isEmergency= */ false);
+        expectedAddresses = getInetAddresses(TEST_IPV4_ADDRESS_3);
+        assertEquals(expectedAddresses, actualAddresses);
+
+        mEpdgSelector.onEpdgConnectionFailed(
+                InetAddress.getByName(TEST_IPV4_ADDRESS_3), mockIkeIOException);
         // It should also reset the excluded list once all ip addresses are excluded
-        testInetAddresses = getValidatedServerListWithDefaultParams(false);
-        assertArrayEquals(
-                List.of(
-                                InetAddress.getByName(TEST_IP_ADDRESS_3),
-                                InetAddress.getByName(TEST_IP_ADDRESS_1))
-                        .toArray(),
-                testInetAddresses.toArray());
+        actualAddresses = getValidatedServerListWithDefaultParams(/* isEmergency= */ false);
+        expectedAddresses = getInetAddresses(TEST_IPV4_ADDRESS_3, TEST_IPV4_ADDRESS_1);
+        assertEquals(expectedAddresses, actualAddresses);
     }
 
-    private void setAnswerForCellularMethod(boolean isEmergency, int mcc, int mnc)
-            throws Exception {
+    private void setAnswerForCellularMethod(boolean isEmergency, int mcc, int mnc) {
         String expectedFqdn1 =
                 (isEmergency)
                         ? "lacffcc.sos.epdg.epc.mnc" + mnc + ".mcc" + mcc + ".pub.3gppnetwork.org"
@@ -963,22 +869,64 @@ public class EpdgSelectorTest {
                                 + mcc
                                 + ".pub.3gppnetwork.org";
 
-        mFakeDns.setAnswer(expectedFqdn1, new String[] {TEST_IP_ADDRESS}, TYPE_A);
-        mFakeDns.setAnswer(expectedFqdn2, new String[] {TEST_IP_ADDRESS_1}, TYPE_A);
-        mFakeDns.setAnswer(expectedFqdn3, new String[] {TEST_IP_ADDRESS_2}, TYPE_A);
+        mFakeDns.setAnswer(expectedFqdn1, new String[] {TEST_IPV4_ADDRESS}, TYPE_A);
+        mFakeDns.setAnswer(expectedFqdn2, new String[] {TEST_IPV4_ADDRESS_1}, TYPE_A);
+        mFakeDns.setAnswer(expectedFqdn3, new String[] {TEST_IPV4_ADDRESS_2}, TYPE_A);
+    }
+
+    @Test
+    public void testShouldNotTemporaryExcludedIpAddressWhenInternalError() throws Exception {
+        doReturn(true).when(mfakeFeatureFlags).epdgSelectionExcludeFailedIpAddress();
+        when(DnsResolver.getInstance()).thenReturn(mMockDnsResolver);
+
+        final String fqdnFromRplmn = "epdg.epc.mnc122.mcc300.pub.3gppnetwork.org";
+        final String staticAddr = "epdg.epc.mnc120.mcc300.pub.3gppnetwork.org";
+
+        final IkeNetworkLostException mockIkeNetworkLostException =
+                mock(IkeNetworkLostException.class);
+
+        when(mMockTelephonyManager.getNetworkOperator()).thenReturn("300122");
+        IwlanCarrierConfig.putTestConfigStringArray(
+                CarrierConfigManager.Iwlan.KEY_MCC_MNCS_STRING_ARRAY, new String[] {"300-122"});
+
+        IwlanCarrierConfig.putTestConfigIntArray(
+                CarrierConfigManager.Iwlan.KEY_EPDG_ADDRESS_PRIORITY_INT_ARRAY,
+                new int[] {
+                    CarrierConfigManager.Iwlan.EPDG_ADDRESS_PLMN,
+                    CarrierConfigManager.Iwlan.EPDG_ADDRESS_STATIC
+                });
+        IwlanCarrierConfig.putTestConfigIntArray(
+                CarrierConfigManager.Iwlan.KEY_EPDG_PLMN_PRIORITY_INT_ARRAY,
+                new int[] {CarrierConfigManager.Iwlan.EPDG_PLMN_RPLMN});
+
+        IwlanCarrierConfig.putTestConfigString(
+                CarrierConfigManager.Iwlan.KEY_EPDG_STATIC_ADDRESS_STRING, staticAddr);
+
+        mFakeDns.setAnswer(fqdnFromRplmn, new String[] {TEST_IPV4_ADDRESS}, TYPE_A);
+        mFakeDns.setAnswer(
+                staticAddr, new String[] {TEST_IPV4_ADDRESS_1, TEST_IPV6_ADDRESS}, TYPE_A);
+
+        var expectedAddresses =
+                getInetAddresses(TEST_IPV4_ADDRESS, TEST_IPV4_ADDRESS_1, TEST_IPV6_ADDRESS);
+        var actualAddresses = getValidatedServerListWithDefaultParams(false);
+        assertEquals(expectedAddresses, actualAddresses);
+
+        mEpdgSelector.onEpdgConnectionFailed(
+                InetAddressUtils.parseNumericAddress(TEST_IPV4_ADDRESS),
+                mockIkeNetworkLostException);
+        actualAddresses = getValidatedServerListWithDefaultParams(false);
+        assertEquals(expectedAddresses, actualAddresses);
     }
 
     @Test
     public void testGetValidatedServerListIpv4Preferred() throws Exception {
         when(DnsResolver.getInstance()).thenReturn(mMockDnsResolver);
-        doReturn(true).when(mEpdgSelector).hasIpv4Address(mMockNetwork);
-        doReturn(true).when(mEpdgSelector).hasIpv6Address(mMockNetwork);
 
         final String addr1 = "epdg.epc.mnc120.mcc300.pub.3gppnetwork.org";
         final String addr2 = "epdg.epc.mnc120.mcc311.pub.3gppnetwork.org";
         final String testStaticAddress = addr1 + "," + addr2;
 
-        mFakeDns.setAnswer(addr1, new String[] {TEST_IP_ADDRESS_1}, TYPE_A);
+        mFakeDns.setAnswer(addr1, new String[] {TEST_IPV4_ADDRESS_1}, TYPE_A);
         mFakeDns.setAnswer(addr2, new String[] {TEST_IPV6_ADDRESS}, TYPE_AAAA);
 
         // Set carrier config mock
@@ -988,28 +936,24 @@ public class EpdgSelectorTest {
         IwlanCarrierConfig.putTestConfigString(
                 CarrierConfigManager.Iwlan.KEY_EPDG_STATIC_ADDRESS_STRING, testStaticAddress);
 
-        ArrayList<InetAddress> testInetAddresses =
+        var actualAddresses =
                 getValidatedServerListWithIpPreference(
                         EpdgSelector.PROTO_FILTER_IPV4V6,
                         EpdgSelector.IPV4_PREFERRED,
-                        false /*isEmergency*/);
-
-        assertEquals(2, testInetAddresses.size());
-        assertEquals(InetAddress.getByName(TEST_IP_ADDRESS_1), testInetAddresses.get(0));
-        assertEquals(InetAddress.getByName(TEST_IPV6_ADDRESS), testInetAddresses.get(1));
+                        /* isEmergency= */ false);
+        var expectedAddresses = getInetAddresses(TEST_IPV4_ADDRESS_1, TEST_IPV6_ADDRESS);
+        assertEquals(expectedAddresses, actualAddresses);
     }
 
     @Test
     public void testGetValidatedServerListIpv6Preferred() throws Exception {
         when(DnsResolver.getInstance()).thenReturn(mMockDnsResolver);
-        doReturn(true).when(mEpdgSelector).hasIpv4Address(mMockNetwork);
-        doReturn(true).when(mEpdgSelector).hasIpv6Address(mMockNetwork);
 
         final String addr1 = "epdg.epc.mnc120.mcc300.pub.3gppnetwork.org";
         final String addr2 = "epdg.epc.mnc120.mcc311.pub.3gppnetwork.org";
         final String testStaticAddress = addr1 + "," + addr2;
 
-        mFakeDns.setAnswer(addr1, new String[] {TEST_IP_ADDRESS_1}, TYPE_A);
+        mFakeDns.setAnswer(addr1, new String[] {TEST_IPV4_ADDRESS_1}, TYPE_A);
         mFakeDns.setAnswer(addr2, new String[] {TEST_IPV6_ADDRESS}, TYPE_AAAA);
 
         // Set carrier config mock
@@ -1019,28 +963,24 @@ public class EpdgSelectorTest {
         IwlanCarrierConfig.putTestConfigString(
                 CarrierConfigManager.Iwlan.KEY_EPDG_STATIC_ADDRESS_STRING, testStaticAddress);
 
-        ArrayList<InetAddress> testInetAddresses =
+        var actualAddresses =
                 getValidatedServerListWithIpPreference(
                         EpdgSelector.PROTO_FILTER_IPV4V6,
                         EpdgSelector.IPV6_PREFERRED,
-                        false /*isEmergency*/);
-
-        assertEquals(2, testInetAddresses.size());
-        assertEquals(InetAddress.getByName(TEST_IPV6_ADDRESS), testInetAddresses.get(0));
-        assertEquals(InetAddress.getByName(TEST_IP_ADDRESS_1), testInetAddresses.get(1));
+                        /* isEmergency= */ false);
+        var expectedAddresses = getInetAddresses(TEST_IPV6_ADDRESS, TEST_IPV4_ADDRESS_1);
+        assertEquals(expectedAddresses, actualAddresses);
     }
 
     @Test
     public void testGetValidatedServerListIpv4Only() throws Exception {
         when(DnsResolver.getInstance()).thenReturn(mMockDnsResolver);
-        doReturn(true).when(mEpdgSelector).hasIpv4Address(mMockNetwork);
-        doReturn(true).when(mEpdgSelector).hasIpv6Address(mMockNetwork);
 
         final String addr1 = "epdg.epc.mnc120.mcc300.pub.3gppnetwork.org";
         final String addr2 = "epdg.epc.mnc120.mcc311.pub.3gppnetwork.org";
         final String testStaticAddress = addr1 + "," + addr2;
 
-        mFakeDns.setAnswer(addr1, new String[] {TEST_IP_ADDRESS_1}, TYPE_A);
+        mFakeDns.setAnswer(addr1, new String[] {TEST_IPV4_ADDRESS_1}, TYPE_A);
         mFakeDns.setAnswer(addr2, new String[] {TEST_IPV6_ADDRESS}, TYPE_AAAA);
 
         // Set carrier config mock
@@ -1050,21 +990,18 @@ public class EpdgSelectorTest {
         IwlanCarrierConfig.putTestConfigString(
                 CarrierConfigManager.Iwlan.KEY_EPDG_STATIC_ADDRESS_STRING, testStaticAddress);
 
-        ArrayList<InetAddress> testInetAddresses =
+        var expectedAddresses = getInetAddresses(TEST_IPV4_ADDRESS_1);
+        var actualAddresses =
                 getValidatedServerListWithIpPreference(
                         EpdgSelector.PROTO_FILTER_IPV4,
                         EpdgSelector.SYSTEM_PREFERRED,
-                        false /*isEmergency*/);
-
-        assertEquals(1, testInetAddresses.size());
-        assertEquals(InetAddress.getByName(TEST_IP_ADDRESS_1), testInetAddresses.get(0));
+                        /* isEmergency= */ false);
+        assertEquals(expectedAddresses, actualAddresses);
     }
 
     @Test
     public void testGetValidatedServerListIpv4OnlyCongestion() throws Exception {
         when(DnsResolver.getInstance()).thenReturn(mMockDnsResolver);
-        doReturn(true).when(mEpdgSelector).hasIpv4Address(mMockNetwork);
-        doReturn(true).when(mEpdgSelector).hasIpv6Address(mMockNetwork);
 
         when(mMockErrorPolicyManager.getMostRecentDataFailCause())
                 .thenReturn(DataFailCause.IWLAN_CONGESTION);
@@ -1082,30 +1019,27 @@ public class EpdgSelectorTest {
                 new String[] {"310-480", "300-120", "311-120"});
 
         mFakeDns.setAnswer(expectedFqdnFromHplmn, new String[] {TEST_IPV6_ADDRESS}, TYPE_AAAA);
-        mFakeDns.setAnswer(expectedFqdnFromEHplmn, new String[] {TEST_IP_ADDRESS_1}, TYPE_A);
-        mFakeDns.setAnswer(expectedFqdnFromConfig, new String[] {TEST_IP_ADDRESS_2}, TYPE_A);
+        mFakeDns.setAnswer(expectedFqdnFromEHplmn, new String[] {TEST_IPV4_ADDRESS_1}, TYPE_A);
+        mFakeDns.setAnswer(expectedFqdnFromConfig, new String[] {TEST_IPV4_ADDRESS_2}, TYPE_A);
 
-        ArrayList<InetAddress> testInetAddresses =
+        var expectedAddresses = List.of(InetAddress.getAllByName(TEST_IPV4_ADDRESS_1));
+        var actualAddresses =
                 getValidatedServerListWithIpPreference(
                         EpdgSelector.PROTO_FILTER_IPV4,
                         EpdgSelector.SYSTEM_PREFERRED,
-                        false /*isEmergency*/);
-
-        assertEquals(1, testInetAddresses.size());
-        assertEquals(InetAddress.getByName(TEST_IP_ADDRESS_1), testInetAddresses.get(0));
+                        /* isEmergency= */ false);
+        assertEquals(expectedAddresses, actualAddresses);
     }
 
     @Test
     public void testGetValidatedServerListIpv6Only() throws Exception {
         when(DnsResolver.getInstance()).thenReturn(mMockDnsResolver);
-        doReturn(true).when(mEpdgSelector).hasIpv4Address(mMockNetwork);
-        doReturn(true).when(mEpdgSelector).hasIpv6Address(mMockNetwork);
 
         final String addr1 = "epdg.epc.mnc120.mcc300.pub.3gppnetwork.org";
         final String addr2 = "epdg.epc.mnc120.mcc311.pub.3gppnetwork.org";
         final String testStaticAddress = addr1 + "," + addr2;
 
-        mFakeDns.setAnswer(addr1, new String[] {TEST_IP_ADDRESS_1}, TYPE_A);
+        mFakeDns.setAnswer(addr1, new String[] {TEST_IPV4_ADDRESS_1}, TYPE_A);
         mFakeDns.setAnswer(addr2, new String[] {TEST_IPV6_ADDRESS}, TYPE_AAAA);
 
         // Set carrier config mock
@@ -1115,30 +1049,27 @@ public class EpdgSelectorTest {
         IwlanCarrierConfig.putTestConfigString(
                 CarrierConfigManager.Iwlan.KEY_EPDG_STATIC_ADDRESS_STRING, testStaticAddress);
 
-        ArrayList<InetAddress> testInetAddresses =
+        var expectedAddresses = List.of(InetAddress.getAllByName(TEST_IPV6_ADDRESS));
+        var actualAddresses =
                 getValidatedServerListWithIpPreference(
                         EpdgSelector.PROTO_FILTER_IPV6,
                         EpdgSelector.SYSTEM_PREFERRED,
-                        false /*isEmergency*/);
-
-        assertEquals(1, testInetAddresses.size());
-        assertEquals(InetAddress.getByName(TEST_IPV6_ADDRESS), testInetAddresses.get(0));
+                        /* isEmergency= */ false);
+        assertEquals(expectedAddresses, actualAddresses);
     }
 
     @Test
     public void testGetValidatedServerListSystemPreferred() throws Exception {
         when(DnsResolver.getInstance()).thenReturn(mMockDnsResolver);
-        doReturn(true).when(mEpdgSelector).hasIpv4Address(mMockNetwork);
-        doReturn(true).when(mEpdgSelector).hasIpv6Address(mMockNetwork);
 
         final String addr1 = "epdg.epc.mnc120.mcc300.pub.3gppnetwork.org";
         final String addr2 = "epdg.epc.mnc120.mcc311.pub.3gppnetwork.org";
         final String addr3 = "epdg.epc.mnc120.mcc312.pub.3gppnetwork.org";
         final String testStaticAddress = addr1 + "," + addr2 + "," + addr3;
 
-        mFakeDns.setAnswer(addr1, new String[] {TEST_IP_ADDRESS_1}, TYPE_A);
+        mFakeDns.setAnswer(addr1, new String[] {TEST_IPV4_ADDRESS_1}, TYPE_A);
         mFakeDns.setAnswer(addr2, new String[] {TEST_IPV6_ADDRESS}, TYPE_AAAA);
-        mFakeDns.setAnswer(addr3, new String[] {TEST_IP_ADDRESS_2}, TYPE_A);
+        mFakeDns.setAnswer(addr3, new String[] {TEST_IPV4_ADDRESS_2}, TYPE_A);
 
         // Set carrier config mock
         IwlanCarrierConfig.putTestConfigIntArray(
@@ -1147,16 +1078,14 @@ public class EpdgSelectorTest {
         IwlanCarrierConfig.putTestConfigString(
                 CarrierConfigManager.Iwlan.KEY_EPDG_STATIC_ADDRESS_STRING, testStaticAddress);
 
-        ArrayList<InetAddress> testInetAddresses =
+        var actualAddresses =
                 getValidatedServerListWithIpPreference(
                         EpdgSelector.PROTO_FILTER_IPV4V6,
                         EpdgSelector.SYSTEM_PREFERRED,
-                        false /*isEmergency*/);
-
-        assertEquals(3, testInetAddresses.size());
-        assertEquals(InetAddress.getByName(TEST_IP_ADDRESS_1), testInetAddresses.get(0));
-        assertEquals(InetAddress.getByName(TEST_IPV6_ADDRESS), testInetAddresses.get(1));
-        assertEquals(InetAddress.getByName(TEST_IP_ADDRESS_2), testInetAddresses.get(2));
+                        /* isEmergency= */ false);
+        var expectedAddresses =
+                getInetAddresses(TEST_IPV4_ADDRESS_1, TEST_IPV6_ADDRESS, TEST_IPV4_ADDRESS_2);
+        assertEquals(expectedAddresses, actualAddresses);
     }
 
     /**
@@ -1167,7 +1096,7 @@ public class EpdgSelectorTest {
      */
     class FakeDns {
         /** Data class to record the Dns entry. */
-        class DnsEntry {
+        static class DnsEntry {
             final String mHostname;
             final int mType;
             final List<InetAddress> mAddresses;
@@ -1177,6 +1106,7 @@ public class EpdgSelectorTest {
                 mType = type;
                 mAddresses = addr;
             }
+
             // Full match or partial match that target host contains the entry hostname to support
             // random private dns probe hostname.
             private boolean matches(String hostname, int type) {
@@ -1201,8 +1131,7 @@ public class EpdgSelectorTest {
         }
 
         /** Sets the answer for a given name and type. */
-        private synchronized void setAnswer(String hostname, String[] answer, int type)
-                throws UnknownHostException {
+        private synchronized void setAnswer(String hostname, String[] answer, int type) {
             DnsEntry record = new DnsEntry(hostname, type, generateAnswer(answer));
             // Remove the existing one.
             mAnswers.removeIf(entry -> entry.matches(hostname, type));
@@ -1212,9 +1141,7 @@ public class EpdgSelectorTest {
 
         private List<InetAddress> generateAnswer(String[] answer) {
             if (answer == null) return new ArrayList<>();
-            return Arrays.stream(answer)
-                    .map(addr -> InetAddresses.parseNumericAddress(addr))
-                    .collect(toList());
+            return Arrays.stream(answer).map(InetAddresses::parseNumericAddress).collect(toList());
         }
 
         // Regardless of the type, depends on what the responses contained in the network.
@@ -1235,70 +1162,47 @@ public class EpdgSelectorTest {
             return answer;
         }
 
-        private void addAllIfNotNull(List<InetAddress> list, List<InetAddress> c) {
-            if (c != null) {
-                list.addAll(c);
-            }
-        }
-
         /** Starts mocking DNS queries. */
-        private void startMocking() throws UnknownHostException {
+        private void startMocking() {
             // 5-arg DnsResolver.query()
             doAnswer(
-                            invocation -> {
-                                return mockQuery(
-                                        invocation,
-                                        1 /* posHostname */,
-                                        -1 /* posType */,
-                                        3 /* posExecutor */,
-                                        5 /* posCallback */);
-                            })
+                            invocation ->
+                                    mockQuery(
+                                            invocation,
+                                            /* posType= */ -1,
+                                            /* posExecutor= */ 3,
+                                            /* posCallback= */ 5))
                     .when(mMockDnsResolver)
                     .query(any(), anyString(), anyInt(), any(), any(), any());
 
             // 6-arg DnsResolver.query() with explicit query type (IPv4 or v6).
             doAnswer(
-                            invocation -> {
-                                return mockQuery(
-                                        invocation,
-                                        1 /* posHostname */,
-                                        2 /* posType */,
-                                        4 /* posExecutor */,
-                                        6 /* posCallback */);
-                            })
+                            invocation ->
+                                    mockQuery(
+                                            invocation,
+                                            /* posType= */ 2,
+                                            /* posExecutor= */ 4,
+                                            /* posCallback= */ 6))
                     .when(mMockDnsResolver)
                     .query(any(), anyString(), anyInt(), anyInt(), any(), any(), any());
         }
 
         // Mocking queries on DnsResolver#query.
-        private Answer mockQuery(
-                InvocationOnMock invocation,
-                int posHostname,
-                int posType,
-                int posExecutor,
-                int posCallback) {
-            String hostname = invocation.getArgument(posHostname);
+        private Answer<?> mockQuery(
+                InvocationOnMock invocation, int posType, int posExecutor, int posCallback) {
+            String hostname = invocation.getArgument(1);
             Executor executor = invocation.getArgument(posExecutor);
             DnsResolver.Callback<List<InetAddress>> callback = invocation.getArgument(posCallback);
-            List<InetAddress> answer;
-
-            switch (posType) {
-                case TYPE_A:
-                    answer = queryIpv4(hostname);
-                    break;
-                case TYPE_AAAA:
-                    answer = queryIpv6(hostname);
-                    break;
-                default:
-                    answer = queryAllTypes(hostname);
-            }
-
-            if (answer != null && answer.size() > 0) {
+            List<InetAddress> answer =
+                    switch (posType) {
+                        case TYPE_A -> queryIpv4(hostname);
+                        case TYPE_AAAA -> queryIpv6(hostname);
+                        default -> queryAllTypes(hostname);
+                    };
+
+            if (answer != null && !answer.isEmpty()) {
                 new Handler(Looper.getMainLooper())
-                        .post(
-                                () -> {
-                                    executor.execute(() -> callback.onAnswer(answer, 0));
-                                });
+                        .post(() -> executor.execute(() -> callback.onAnswer(answer, 0)));
             }
             // If no answers, do nothing. sendDnsProbeWithTimeout will time out and throw UHE.
             return null;
@@ -1307,7 +1211,7 @@ public class EpdgSelectorTest {
 
     @SuppressWarnings("FutureReturnValueIgnored")
     @Test
-    public void testMultipleBackToBackSetupDataCallRequest() throws Exception {
+    public void testMultipleBackToBackSetupDataCallRequest() {
         when(mfakeFeatureFlags.preventEpdgSelectionThreadsExhausted()).thenReturn(true);
         EpdgSelector epdgSelector =
                 new EpdgSelector(mMockContext, DEFAULT_SLOT_INDEX, mfakeFeatureFlags);
@@ -1322,7 +1226,7 @@ public class EpdgSelectorTest {
 
     @SuppressWarnings("FutureReturnValueIgnored")
     @Test
-    public void testBackToBackSetupDataCallRequest() throws Exception {
+    public void testBackToBackSetupDataCallRequest() {
         when(mfakeFeatureFlags.preventEpdgSelectionThreadsExhausted()).thenReturn(false);
         EpdgSelector epdgSelector =
                 new EpdgSelector(mMockContext, DEFAULT_SLOT_INDEX, mfakeFeatureFlags);
@@ -1336,4 +1240,156 @@ public class EpdgSelectorTest {
                 RejectedExecutionException.class,
                 () -> epdgSelector.trySubmitEpdgSelectionExecutor(runnable, false, false));
     }
+
+    private void sendCarrierSignalPcoValue(int apnType, int pcoId, byte[] pcoData) {
+        // Create intent object
+        final Intent intent = new Intent(TelephonyManager.ACTION_CARRIER_SIGNAL_PCO_VALUE);
+        intent.putExtra(TelephonyManager.EXTRA_APN_TYPE, apnType);
+        intent.putExtra(TelephonyManager.EXTRA_PCO_ID, pcoId);
+        intent.putExtra(TelephonyManager.EXTRA_PCO_VALUE, pcoData);
+        // Trigger onReceive method
+        mEpdgSelector.processCarrierSignalPcoValue(intent);
+    }
+
+    @Test
+    public void testProcessCarrierSignalPcoValue_ipv4() throws Exception {
+        addTestPcoIdsToTestConfigBundle();
+
+        sendCarrierSignalPcoValue(ApnSetting.TYPE_IMS, TEST_PCO_ID_IPV4, TEST_PCO_IPV4_DATA);
+
+        var expectedAddresses = new HashSet<>(getInetAddresses(TEST_IPV4_ADDRESS));
+        var actualAddresses =
+                new HashSet<>(
+                        getValidatedServerListWithIpPreference(
+                                EpdgSelector.PROTO_FILTER_IPV4,
+                                EpdgSelector.IPV4_PREFERRED,
+                                /* isEmergency= */ false));
+        assertEquals(expectedAddresses, actualAddresses);
+    }
+
+    @Test
+    public void testProcessCarrierSignalPcoValue_ipv6() throws Exception {
+        addTestPcoIdsToTestConfigBundle();
+
+        sendCarrierSignalPcoValue(ApnSetting.TYPE_IMS, TEST_PCO_ID_IPV6, TEST_PCO_IPV6_DATA);
+
+        var expectedAddresses = new HashSet<>(getInetAddresses(TEST_IPV6_ADDRESS));
+        var actualAddresses =
+                new HashSet<>(
+                        getValidatedServerListWithIpPreference(
+                                EpdgSelector.PROTO_FILTER_IPV6,
+                                EpdgSelector.IPV6_PREFERRED,
+                                /* isEmergency= */ false));
+        assertEquals(expectedAddresses, actualAddresses);
+    }
+
+    @Test
+    public void testProcessCarrierSignalPcoValue_ipv4v6() throws Exception {
+        addTestPcoIdsToTestConfigBundle();
+
+        sendCarrierSignalPcoValue(ApnSetting.TYPE_IMS, TEST_PCO_ID_IPV6, TEST_PCO_IPV6_DATA);
+        sendCarrierSignalPcoValue(ApnSetting.TYPE_IMS, TEST_PCO_ID_IPV4, TEST_PCO_IPV4_DATA);
+
+        var expectedAddresses =
+                new HashSet<>(getInetAddresses(TEST_IPV4_ADDRESS, TEST_IPV6_ADDRESS));
+        var actualAddresses =
+                new HashSet<>(getValidatedServerListWithDefaultParams(/* isEmergency= */ false));
+        assertEquals(expectedAddresses, actualAddresses);
+    }
+
+    @Test
+    public void testProcessCarrierSignalPcoValue_incorrectApnType_noAddress() throws Exception {
+        addTestPcoIdsToTestConfigBundle();
+
+        sendCarrierSignalPcoValue(ApnSetting.TYPE_NONE, TEST_PCO_ID_IPV4, TEST_PCO_IPV4_DATA);
+
+        List<InetAddress> actualAddresses =
+                getValidatedServerListWithIpPreference(
+                        EpdgSelector.PROTO_FILTER_IPV4,
+                        EpdgSelector.IPV4_PREFERRED,
+                        /* isEmergency= */ false);
+        assertEquals(0, actualAddresses.size());
+    }
+
+    @Test
+    public void testProcessCarrierSignalPcoValue_invalidPcoId_noAddress() throws Exception {
+        addTestPcoIdsToTestConfigBundle();
+
+        sendCarrierSignalPcoValue(ApnSetting.TYPE_IMS, TEST_PCO_ID_INVALID, TEST_PCO_IPV4_DATA);
+
+        List<InetAddress> actualAddresses =
+                getValidatedServerListWithIpPreference(
+                        EpdgSelector.PROTO_FILTER_IPV4,
+                        EpdgSelector.IPV4_PREFERRED,
+                        /* isEmergency= */ false);
+        assertEquals(0, actualAddresses.size());
+    }
+
+    @Test
+    public void testProcessCarrierSignalPcoValue_nullPcoData_noAddress() throws Exception {
+        addTestPcoIdsToTestConfigBundle();
+
+        sendCarrierSignalPcoValue(ApnSetting.TYPE_IMS, TEST_PCO_ID_IPV4, /* pcoData= */ null);
+        sendCarrierSignalPcoValue(ApnSetting.TYPE_IMS, TEST_PCO_ID_IPV6, /* pcoData= */ null);
+
+        List<InetAddress> actualIpv4Addresses =
+                getValidatedServerListWithIpPreference(
+                        EpdgSelector.PROTO_FILTER_IPV4,
+                        EpdgSelector.IPV4_PREFERRED,
+                        /* isEmergency= */ false);
+        List<InetAddress> actualIpv6Addresses =
+                getValidatedServerListWithIpPreference(
+                        EpdgSelector.PROTO_FILTER_IPV6,
+                        EpdgSelector.IPV6_PREFERRED,
+                        /* isEmergency= */ false);
+        assertEquals(0, actualIpv4Addresses.size());
+        assertEquals(0, actualIpv6Addresses.size());
+    }
+
+    @Test
+    public void testGetValidatedServerList_ignoreIpv6UniqueLocalAddress() throws Exception {
+        String uniqueLocalAddress = "fdd3:ebb6:b1bd:da46:8900:b105:515c:fe62";
+
+        applyTestAddressToNetwork(
+                List.of(
+                        new LinkAddress(InetAddress.getByName(TEST_LOCAL_IPV4_ADDRESS), 24),
+                        new LinkAddress(InetAddress.getByName(uniqueLocalAddress), 64)));
+        applyTestAddressToNetworkForFamily(EpdgSelector.PROTO_FILTER_IPV4);
+        when(DnsResolver.getInstance()).thenReturn(mMockDnsResolver);
+
+        String fqdnIpv6 = "epdg.epc.mnc120.mcc300.pub.3gppnetwork.org";
+        String fqdnIpv4 = "epdg.epc.mnc120.mcc311.pub.3gppnetwork.org";
+
+        mFakeDns.setAnswer(fqdnIpv6, new String[] {TEST_IPV6_ADDRESS}, TYPE_AAAA);
+        mFakeDns.setAnswer(fqdnIpv4, new String[] {TEST_IPV4_ADDRESS}, TYPE_A);
+
+        List<InetAddress> expectedAddresses = getInetAddresses(TEST_IPV4_ADDRESS);
+        List<InetAddress> actualAddresses =
+                getValidatedServerListWithIpPreference(
+                        EpdgSelector.PROTO_FILTER_IPV4V6,
+                        EpdgSelector.SYSTEM_PREFERRED,
+                        /* isEmergency= */ false);
+
+        assertEquals(expectedAddresses, actualAddresses);
+    }
+
+    private void applyTestAddressToNetwork(Collection<LinkAddress> addresses) {
+        mTestLinkProperties.setLinkAddresses(addresses);
+    }
+
+    private void applyTestAddressToNetworkForFamily(int filter) throws Exception {
+        List<LinkAddress> addresses = new ArrayList<>();
+
+        if (filter == EpdgSelector.PROTO_FILTER_IPV4
+                || filter == EpdgSelector.PROTO_FILTER_IPV4V6) {
+            addresses.add(new LinkAddress(InetAddress.getByName(TEST_LOCAL_IPV4_ADDRESS), 24));
+        }
+
+        if (filter == EpdgSelector.PROTO_FILTER_IPV6
+                || filter == EpdgSelector.PROTO_FILTER_IPV4V6) {
+            addresses.add(new LinkAddress(InetAddress.getByName(TEST_LOCAL_IPV6_ADDRESS), 64));
+        }
+
+        mTestLinkProperties.setLinkAddresses(addresses);
+    }
 }
diff --git a/test/com/google/android/iwlan/epdg/EpdgTunnelManagerTest.java b/test/com/google/android/iwlan/epdg/EpdgTunnelManagerTest.java
index 264a9c6..55b40b1 100644
--- a/test/com/google/android/iwlan/epdg/EpdgTunnelManagerTest.java
+++ b/test/com/google/android/iwlan/epdg/EpdgTunnelManagerTest.java
@@ -16,7 +16,10 @@
 
 package com.google.android.iwlan.epdg;
 
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.mockitoSession;
+
 import static com.google.android.iwlan.epdg.EpdgTunnelManager.BRINGDOWN_REASON_UNKNOWN;
+import static com.google.android.iwlan.proto.MetricsAtom.*;
 
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
@@ -43,6 +46,8 @@ import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
 import android.content.Context;
+import android.net.ConnectivityDiagnosticsManager;
+import android.net.ConnectivityDiagnosticsManager.ConnectivityReport;
 import android.net.ConnectivityManager;
 import android.net.InetAddresses;
 import android.net.IpSecManager;
@@ -65,10 +70,12 @@ import android.net.ipsec.ike.TunnelModeChildSessionParams;
 import android.net.ipsec.ike.exceptions.IkeException;
 import android.net.ipsec.ike.exceptions.IkeIOException;
 import android.net.ipsec.ike.exceptions.IkeInternalException;
+import android.net.ipsec.ike.exceptions.IkeNetworkLostException;
 import android.net.ipsec.ike.exceptions.IkeProtocolException;
 import android.net.ipsec.ike.ike3gpp.Ike3gppBackoffTimer;
 import android.net.ipsec.ike.ike3gpp.Ike3gppData;
 import android.net.ipsec.ike.ike3gpp.Ike3gppExtension;
+import android.os.PersistableBundle;
 import android.os.test.TestLooper;
 import android.telephony.CarrierConfigManager;
 import android.telephony.PreciseDataConnectionState;
@@ -78,24 +85,26 @@ import android.telephony.TelephonyManager;
 import android.telephony.data.ApnSetting;
 import android.util.Pair;
 
+import com.google.android.iwlan.ErrorPolicyManager;
 import com.google.android.iwlan.IwlanCarrierConfig;
 import com.google.android.iwlan.IwlanError;
-import com.google.android.iwlan.IwlanTunnelMetricsImpl;
+import com.google.android.iwlan.IwlanHelper;
+import com.google.android.iwlan.IwlanStatsLog;
 import com.google.android.iwlan.TunnelMetricsInterface.OnClosedMetrics;
 import com.google.android.iwlan.TunnelMetricsInterface.OnOpenedMetrics;
 import com.google.android.iwlan.flags.FeatureFlags;
+import com.google.android.iwlan.proto.MetricsAtom;
 
 import org.junit.After;
 import org.junit.Before;
-import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
 import org.mockito.ArgumentCaptor;
 import org.mockito.Mock;
-import org.mockito.internal.util.reflection.FieldSetter;
-import org.mockito.junit.MockitoJUnit;
-import org.mockito.junit.MockitoRule;
+import org.mockito.MockitoAnnotations;
+import org.mockito.MockitoSession;
+import org.mockito.quality.Strictness;
 
 import java.io.IOException;
 import java.net.Inet4Address;
@@ -138,24 +147,27 @@ public class EpdgTunnelManagerTest {
     private EpdgTunnelManager mEpdgTunnelManager;
 
     private static class IwlanTunnelCallback implements EpdgTunnelManager.TunnelCallback {
-        public void onOpened(String apnName, TunnelLinkProperties linkProperties) {}
+        public void onOpened(
+                String apnName,
+                TunnelLinkProperties linkProperties,
+                OnOpenedMetrics onOpenedMetrics) {}
 
-        public void onClosed(String apnName, IwlanError error) {}
+        public void onClosed(String apnName, IwlanError error, OnClosedMetrics onClosedMetrics) {}
 
         public void onNetworkValidationStatusChanged(String apnName, int status) {}
     }
 
-    @Rule public final MockitoRule mockito = MockitoJUnit.rule();
     private final TestLooper mTestLooper = new TestLooper();
 
     @Mock private Context mMockContext;
     @Mock private Network mMockDefaultNetwork;
     @Mock private IwlanTunnelCallback mMockIwlanTunnelCallback;
-    @Mock private IwlanTunnelMetricsImpl mMockIwlanTunnelMetrics;
     @Mock private IkeSession mMockIkeSession;
     @Mock private EpdgSelector mMockEpdgSelector;
+    @Mock private ErrorPolicyManager mMockErrorPolicyManager;
     @Mock private FeatureFlags mFakeFeatureFlags;
     @Mock ConnectivityManager mMockConnectivityManager;
+    @Mock ConnectivityDiagnosticsManager mMockConnectivityDiagnosticsManager;
     @Mock SubscriptionManager mMockSubscriptionManager;
     @Mock SubscriptionInfo mMockSubscriptionInfo;
     @Mock TelephonyManager mMockTelephonyManager;
@@ -171,6 +183,12 @@ public class EpdgTunnelManagerTest {
     @Mock IpSecTransform mMockedIpSecTransformOut;
     @Mock LinkProperties mMockLinkProperties;
     @Mock NetworkCapabilities mMockNetworkCapabilities;
+    private MockitoSession mMockitoSession;
+    private long mMockedClockTime = 0;
+    private final ArgumentCaptor<ConnectivityDiagnosticsManager.ConnectivityDiagnosticsCallback>
+            mConnectivityDiagnosticsCallbackArgumentCaptor =
+                    ArgumentCaptor.forClass(
+                            ConnectivityDiagnosticsManager.ConnectivityDiagnosticsCallback.class);
 
     static class IkeSessionArgumentCaptors {
         ArgumentCaptor<IkeSessionParams> mIkeSessionParamsCaptor =
@@ -185,27 +203,48 @@ public class EpdgTunnelManagerTest {
 
     @Before
     public void setUp() throws Exception {
+        // TODO: replace with ExtendedMockitoRule?
+        MockitoAnnotations.initMocks(this);
+        mMockitoSession =
+                mockitoSession()
+                        .mockStatic(EpdgSelector.class)
+                        .mockStatic(ErrorPolicyManager.class)
+                        .mockStatic(IwlanStatsLog.class)
+                        .spyStatic(IwlanHelper.class)
+                        .strictness(Strictness.LENIENT)
+                        .startMocking();
+        mMockedClockTime = 0;
+        when(IwlanHelper.elapsedRealtime()).thenAnswer(i -> mMockedClockTime);
         EpdgTunnelManager.resetAllInstances();
+        ErrorPolicyManager.resetAllInstances();
+
+        when(EpdgSelector.getSelectorInstance(eq(mMockContext), eq(DEFAULT_SLOT_INDEX)))
+                .thenReturn(mMockEpdgSelector);
+        when(ErrorPolicyManager.getInstance(eq(mMockContext), eq(DEFAULT_SLOT_INDEX)))
+                .thenReturn(mMockErrorPolicyManager);
         when(mMockContext.getSystemService(eq(ConnectivityManager.class)))
                 .thenReturn(mMockConnectivityManager);
         when(mMockContext.getSystemService(eq(SubscriptionManager.class)))
                 .thenReturn(mMockSubscriptionManager);
         when(mMockContext.getSystemService(eq(TelephonyManager.class)))
                 .thenReturn(mMockTelephonyManager);
+        when(mMockContext.getSystemService(eq(ConnectivityDiagnosticsManager.class)))
+                .thenReturn(mMockConnectivityDiagnosticsManager);
         when(mMockTelephonyManager.createForSubscriptionId(DEFAULT_SUBID))
                 .thenReturn(mMockTelephonyManager);
+        when(mMockTelephonyManager.getSimCarrierId()).thenReturn(0);
         when(mMockContext.getSystemService(eq(IpSecManager.class))).thenReturn(mMockIpSecManager);
         when(mFakeFeatureFlags.epdgSelectionExcludeFailedIpAddress()).thenReturn(false);
         when(mMockConnectivityManager.getNetworkCapabilities(any(Network.class)))
                 .thenReturn(mMockNetworkCapabilities);
         when(mMockNetworkCapabilities.hasCapability(anyInt())).thenReturn(false);
-
         mEpdgTunnelManager =
                 spy(new EpdgTunnelManager(mMockContext, DEFAULT_SLOT_INDEX, mFakeFeatureFlags));
+        verify(mMockConnectivityDiagnosticsManager)
+                .registerConnectivityDiagnosticsCallback(
+                        any(), any(), mConnectivityDiagnosticsCallbackArgumentCaptor.capture());
         doReturn(mTestLooper.getLooper()).when(mEpdgTunnelManager).getLooper();
-        setVariable(mEpdgTunnelManager, "mContext", mMockContext);
         mEpdgTunnelManager.initHandler();
-        doReturn(mMockEpdgSelector).when(mEpdgTunnelManager).getEpdgSelector();
         when(mEpdgTunnelManager.getIkeSessionCreator()).thenReturn(mMockIkeSessionCreator);
 
         when(mMockEpdgSelector.getValidatedServerList(
@@ -247,6 +286,7 @@ public class EpdgTunnelManagerTest {
     @After
     public void cleanUp() {
         IwlanCarrierConfig.resetTestConfig();
+        mMockitoSession.finishMocking();
     }
 
     @Test
@@ -254,8 +294,7 @@ public class EpdgTunnelManagerTest {
         boolean ret =
                 mEpdgTunnelManager.bringUpTunnel(
                         getBasicTunnelSetupRequest(TEST_APN_NAME, ApnSetting.PROTOCOL_PPP),
-                        mMockIwlanTunnelCallback,
-                        mMockIwlanTunnelMetrics);
+                        mMockIwlanTunnelCallback);
         assertFalse(ret);
     }
 
@@ -264,15 +303,13 @@ public class EpdgTunnelManagerTest {
         boolean ret =
                 mEpdgTunnelManager.bringUpTunnel(
                         getBasicTunnelSetupRequest(TEST_APN_NAME, ApnSetting.PROTOCOL_IPV6, 16),
-                        mMockIwlanTunnelCallback,
-                        mMockIwlanTunnelMetrics);
+                        mMockIwlanTunnelCallback);
         assertFalse(ret);
 
         ret =
                 mEpdgTunnelManager.bringUpTunnel(
                         getBasicTunnelSetupRequest(TEST_APN_NAME, ApnSetting.PROTOCOL_IPV6, -1),
-                        mMockIwlanTunnelCallback,
-                        mMockIwlanTunnelMetrics);
+                        mMockIwlanTunnelCallback);
         assertFalse(ret);
     }
 
@@ -291,19 +328,13 @@ public class EpdgTunnelManagerTest {
         TunnelSetupRequest TSR_v4v6 =
                 getBasicTunnelSetupRequest(testApnName3, ApnSetting.PROTOCOL_IPV4V6);
 
-        boolean ret =
-                mEpdgTunnelManager.bringUpTunnel(
-                        TSR_v4, mMockIwlanTunnelCallback, mMockIwlanTunnelMetrics);
+        boolean ret = mEpdgTunnelManager.bringUpTunnel(TSR_v4, mMockIwlanTunnelCallback);
         assertTrue(ret);
 
-        ret =
-                mEpdgTunnelManager.bringUpTunnel(
-                        TSR_v6, mMockIwlanTunnelCallback, mMockIwlanTunnelMetrics);
+        ret = mEpdgTunnelManager.bringUpTunnel(TSR_v6, mMockIwlanTunnelCallback);
         assertTrue(ret);
 
-        ret =
-                mEpdgTunnelManager.bringUpTunnel(
-                        TSR_v4v6, mMockIwlanTunnelCallback, mMockIwlanTunnelMetrics);
+        ret = mEpdgTunnelManager.bringUpTunnel(TSR_v4v6, mMockIwlanTunnelCallback);
         assertTrue(ret);
     }
 
@@ -314,9 +345,7 @@ public class EpdgTunnelManagerTest {
 
         when(mEpdgTunnelManager.getTunnelSetupRequestApnName(TSR)).thenReturn(null);
 
-        boolean ret =
-                mEpdgTunnelManager.bringUpTunnel(
-                        TSR, mMockIwlanTunnelCallback, mMockIwlanTunnelMetrics);
+        boolean ret = mEpdgTunnelManager.bringUpTunnel(TSR, mMockIwlanTunnelCallback);
         assertFalse(ret);
         verify(mEpdgTunnelManager).getTunnelSetupRequestApnName(TSR);
     }
@@ -327,9 +356,7 @@ public class EpdgTunnelManagerTest {
 
         when(mEpdgTunnelManager.isTunnelConfigContainExistApn(TEST_APN_NAME)).thenReturn(true);
 
-        boolean ret =
-                mEpdgTunnelManager.bringUpTunnel(
-                        TSR, mMockIwlanTunnelCallback, mMockIwlanTunnelMetrics);
+        boolean ret = mEpdgTunnelManager.bringUpTunnel(TSR, mMockIwlanTunnelCallback);
         assertFalse(ret);
         verify(mEpdgTunnelManager).isTunnelConfigContainExistApn(TEST_APN_NAME);
     }
@@ -344,16 +371,13 @@ public class EpdgTunnelManagerTest {
                 testApnName2,
                 mMockIkeSession,
                 mMockIwlanTunnelCallback,
-                mMockIwlanTunnelMetrics,
                 mMockIpSecTunnelInterface,
                 null /* srcIpv6Addr */,
                 0 /* srcIPv6AddrPrefixLen */,
                 false /* isEmergency */,
                 mEpdgTunnelManager.mEpdgMonitor.getEpdgAddressForNormalSession());
 
-        boolean ret =
-                mEpdgTunnelManager.bringUpTunnel(
-                        TSR, mMockIwlanTunnelCallback, mMockIwlanTunnelMetrics);
+        boolean ret = mEpdgTunnelManager.bringUpTunnel(TSR, mMockIwlanTunnelCallback);
         assertTrue(ret);
     }
 
@@ -362,9 +386,7 @@ public class EpdgTunnelManagerTest {
 
         TunnelSetupRequest TSR = getBasicTunnelSetupRequest(TEST_APN_NAME, ApnSetting.PROTOCOL_IP);
 
-        boolean ret =
-                mEpdgTunnelManager.bringUpTunnel(
-                        TSR, mMockIwlanTunnelCallback, mMockIwlanTunnelMetrics);
+        boolean ret = mEpdgTunnelManager.bringUpTunnel(TSR, mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -379,6 +401,11 @@ public class EpdgTunnelManagerTest {
                         any());
     }
 
+    private void advanceClockByTimeMs(long time) {
+        mMockedClockTime += time;
+        mTestLooper.dispatchAll();
+    }
+
     private void setupTunnelBringup(
             String apnName, List<InetAddress> epdgAddresses, int transactionId) throws Exception {
         doReturn(null)
@@ -394,8 +421,7 @@ public class EpdgTunnelManagerTest {
         boolean ret =
                 mEpdgTunnelManager.bringUpTunnel(
                         getBasicTunnelSetupRequest(apnName, ApnSetting.PROTOCOL_IP),
-                        mMockIwlanTunnelCallback,
-                        mMockIwlanTunnelMetrics);
+                        mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -412,10 +438,6 @@ public class EpdgTunnelManagerTest {
     public void testBringUpTunnelSetsDeviceIdentityImeiSv() throws Exception {
         IwlanCarrierConfig.putTestConfigBoolean(
                 IwlanCarrierConfig.KEY_IKE_DEVICE_IDENTITY_SUPPORTED_BOOL, true);
-        when(mMockContext.getSystemService(eq(TelephonyManager.class)))
-                .thenReturn(mMockTelephonyManager);
-        when(mMockTelephonyManager.createForSubscriptionId(DEFAULT_SUBID))
-                .thenReturn(mMockTelephonyManager);
 
         String TEST_IMEI = "012345678901234";
         String TEST_IMEI_SUFFIX = "56";
@@ -448,10 +470,6 @@ public class EpdgTunnelManagerTest {
     public void testBringUpTunnelSetsDeviceIdentityImei() throws Exception {
         IwlanCarrierConfig.putTestConfigBoolean(
                 IwlanCarrierConfig.KEY_IKE_DEVICE_IDENTITY_SUPPORTED_BOOL, true);
-        when(mMockContext.getSystemService(eq(TelephonyManager.class)))
-                .thenReturn(mMockTelephonyManager);
-        when(mMockTelephonyManager.createForSubscriptionId(DEFAULT_SUBID))
-                .thenReturn(mMockTelephonyManager);
 
         String TEST_IMEI = "012345678901234";
         when(mMockTelephonyManager.getImei()).thenReturn(TEST_IMEI);
@@ -482,10 +500,6 @@ public class EpdgTunnelManagerTest {
     public void testBringUpTunnelNoDeviceIdentityWhenImeiUnavailable() throws Exception {
         IwlanCarrierConfig.putTestConfigBoolean(
                 IwlanCarrierConfig.KEY_IKE_DEVICE_IDENTITY_SUPPORTED_BOOL, true);
-        when(mMockContext.getSystemService(eq(TelephonyManager.class)))
-                .thenReturn(mMockTelephonyManager);
-        when(mMockTelephonyManager.createForSubscriptionId(DEFAULT_SUBID))
-                .thenReturn(mMockTelephonyManager);
         when(mMockTelephonyManager.getImei()).thenReturn(null);
 
         setupTunnelBringup();
@@ -799,16 +813,17 @@ public class EpdgTunnelManagerTest {
                 testApnName,
                 false /*forceClose*/,
                 mMockIwlanTunnelCallback,
-                mMockIwlanTunnelMetrics,
                 BRINGDOWN_REASON_UNKNOWN);
         mTestLooper.dispatchAll();
 
         verify(mEpdgTunnelManager).closePendingRequestsForApn(eq(testApnName));
-        verify(mMockIwlanTunnelCallback)
-                .onClosed(eq(testApnName), eq(new IwlanError(IwlanError.TUNNEL_NOT_FOUND)));
         ArgumentCaptor<OnClosedMetrics> metricsCaptor =
                 ArgumentCaptor.forClass(OnClosedMetrics.class);
-        verify(mMockIwlanTunnelMetrics, times(1)).onClosed(metricsCaptor.capture());
+        verify(mMockIwlanTunnelCallback)
+                .onClosed(
+                        eq(testApnName),
+                        eq(new IwlanError(IwlanError.TUNNEL_NOT_FOUND)),
+                        metricsCaptor.capture());
         assertEquals(testApnName, metricsCaptor.getValue().getApnName());
     }
 
@@ -820,7 +835,6 @@ public class EpdgTunnelManagerTest {
                 testApnName,
                 mMockIkeSession,
                 mMockIwlanTunnelCallback,
-                mMockIwlanTunnelMetrics,
                 mMockIpSecTunnelInterface,
                 null /* srcIpv6Addr */,
                 0 /* srcIPv6AddrPrefixLen */,
@@ -831,7 +845,6 @@ public class EpdgTunnelManagerTest {
                 testApnName,
                 true /*forceClose*/,
                 mMockIwlanTunnelCallback,
-                mMockIwlanTunnelMetrics,
                 BRINGDOWN_REASON_UNKNOWN);
         mTestLooper.dispatchAll();
 
@@ -847,7 +860,6 @@ public class EpdgTunnelManagerTest {
                 testApnName,
                 mMockIkeSession,
                 mMockIwlanTunnelCallback,
-                mMockIwlanTunnelMetrics,
                 mMockIpSecTunnelInterface,
                 null /* srcIpv6Addr */,
                 0 /* srcIPv6AddrPrefixLen */,
@@ -858,7 +870,6 @@ public class EpdgTunnelManagerTest {
                 testApnName,
                 false /*forceClose*/,
                 mMockIwlanTunnelCallback,
-                mMockIwlanTunnelMetrics,
                 BRINGDOWN_REASON_UNKNOWN);
         mTestLooper.dispatchAll();
 
@@ -868,8 +879,6 @@ public class EpdgTunnelManagerTest {
 
     @Test
     public void testRekeyAndNattTimerFromCarrierConfig() throws Exception {
-        String testApnName = "www.xyz.com";
-
         // Test values
         int hardTime = 50000;
         int softTime = 20000;
@@ -901,8 +910,7 @@ public class EpdgTunnelManagerTest {
         boolean ret =
                 mEpdgTunnelManager.bringUpTunnel(
                         getBasicTunnelSetupRequest(TEST_APN_NAME, ApnSetting.PROTOCOL_IP),
-                        mMockIwlanTunnelCallback,
-                        mMockIwlanTunnelMetrics);
+                        mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -935,8 +943,6 @@ public class EpdgTunnelManagerTest {
 
     @Test
     public void testSetRetransmissionTimeoutsFromCarrierConfig() throws Exception {
-        String testApnName = "www.xyz.com";
-
         int[] testTimeouts = {1000, 1200, 1400, 1600, 2000, 4000};
 
         IwlanCarrierConfig.putTestConfigIntArray(
@@ -955,8 +961,7 @@ public class EpdgTunnelManagerTest {
         boolean ret =
                 mEpdgTunnelManager.bringUpTunnel(
                         getBasicTunnelSetupRequest(TEST_APN_NAME, ApnSetting.PROTOCOL_IP),
-                        mMockIwlanTunnelCallback,
-                        mMockIwlanTunnelMetrics);
+                        mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -981,9 +986,6 @@ public class EpdgTunnelManagerTest {
 
     @Test
     public void testSetDpdDelayFromCarrierConfig() throws Exception {
-        String testApnName = "www.xyz.com";
-
-        // Test values
         int testDpdDelay = 600;
 
         IwlanCarrierConfig.putTestConfigInt(
@@ -1002,8 +1004,7 @@ public class EpdgTunnelManagerTest {
         boolean ret =
                 mEpdgTunnelManager.bringUpTunnel(
                         getBasicTunnelSetupRequest(TEST_APN_NAME, ApnSetting.PROTOCOL_IP),
-                        mMockIwlanTunnelCallback,
-                        mMockIwlanTunnelMetrics);
+                        mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -1052,8 +1053,7 @@ public class EpdgTunnelManagerTest {
         boolean ret =
                 mEpdgTunnelManager.bringUpTunnel(
                         getBasicTunnelSetupRequest(TEST_APN_NAME, ApnSetting.PROTOCOL_IP),
-                        mMockIwlanTunnelCallback,
-                        mMockIwlanTunnelMetrics);
+                        mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -1069,8 +1069,8 @@ public class EpdgTunnelManagerTest {
                 new IkeInternalException(new IOException("Retransmitting failure")));
         mTestLooper.dispatchAll();
 
-        verify(mEpdgTunnelManager, times(1)).reportIwlanError(eq(testApnName), eq(error));
-        verify(mMockIwlanTunnelCallback, times(1)).onClosed(eq(testApnName), eq(error));
+        verify(mEpdgTunnelManager).reportIwlanError(eq(testApnName), eq(error));
+        verify(mMockIwlanTunnelCallback).onClosed(eq(testApnName), eq(error), any());
     }
 
     @Test
@@ -1100,8 +1100,7 @@ public class EpdgTunnelManagerTest {
         boolean ret =
                 mEpdgTunnelManager.bringUpTunnel(
                         getBasicTunnelSetupRequest(TEST_APN_NAME, ApnSetting.PROTOCOL_IP),
-                        mMockIwlanTunnelCallback,
-                        mMockIwlanTunnelMetrics);
+                        mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -1118,8 +1117,8 @@ public class EpdgTunnelManagerTest {
                 new IkeInternalException(new IOException("Retransmitting failure")));
         mTestLooper.dispatchAll();
 
-        verify(mEpdgTunnelManager, times(1)).reportIwlanError(eq(testApnName), eq(error));
-        verify(mMockIwlanTunnelCallback, times(1)).onClosed(eq(testApnName), eq(error));
+        verify(mEpdgTunnelManager).reportIwlanError(eq(testApnName), eq(error));
+        verify(mMockIwlanTunnelCallback).onClosed(eq(testApnName), eq(error), any());
     }
 
     @Test
@@ -1149,8 +1148,7 @@ public class EpdgTunnelManagerTest {
         boolean ret =
                 mEpdgTunnelManager.bringUpTunnel(
                         getBasicTunnelSetupRequest(TEST_APN_NAME, ApnSetting.PROTOCOL_IP),
-                        mMockIwlanTunnelCallback,
-                        mMockIwlanTunnelMetrics);
+                        mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -1169,8 +1167,8 @@ public class EpdgTunnelManagerTest {
                 new IkeInternalException(new IOException("Retransmitting failure")));
         mTestLooper.dispatchAll();
 
-        verify(mEpdgTunnelManager, times(1)).reportIwlanError(eq(testApnName), eq(error));
-        verify(mMockIwlanTunnelCallback, times(1)).onClosed(eq(testApnName), eq(error));
+        verify(mEpdgTunnelManager).reportIwlanError(eq(testApnName), eq(error));
+        verify(mMockIwlanTunnelCallback).onClosed(eq(testApnName), eq(error), any());
     }
 
     private EpdgTunnelManager.TmIkeSessionCallback verifyCreateIkeSession(InetAddress ip)
@@ -1199,7 +1197,7 @@ public class EpdgTunnelManagerTest {
         InetAddress src = InetAddress.getByName("2600:381:4872:5d1e:0:10:3582:a501");
         EpdgTunnelManager.TunnelConfig tf =
                 mEpdgTunnelManager
-                .new TunnelConfig(null, null, null, mMockIpSecTunnelInterface, src, 64, false, a1);
+                .new TunnelConfig(null, null, mMockIpSecTunnelInterface, src, 64, false, a1);
         assertTrue(tf.isPrefixSameAsSrcIP(l1));
 
         // different prefix length
@@ -1266,8 +1264,7 @@ public class EpdgTunnelManagerTest {
         boolean ret =
                 mEpdgTunnelManager.bringUpTunnel(
                         getBasicTunnelSetupRequest(TEST_APN_NAME, ApnSetting.PROTOCOL_IP),
-                        mMockIwlanTunnelCallback,
-                        mMockIwlanTunnelMetrics);
+                        mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -1302,13 +1299,13 @@ public class EpdgTunnelManagerTest {
 
         // if expected backoff time is negative - verify that backoff time is not reported.
         if (expectedBackoffTime < 0) {
-            verify(mEpdgTunnelManager, times(1)).reportIwlanError(eq(testApnName), eq(error));
+            verify(mEpdgTunnelManager).reportIwlanError(eq(testApnName), eq(error));
         } else {
             // Else - Verify reportIwlanError with correct backoff time is being called.
-            verify(mEpdgTunnelManager, times(1))
+            verify(mEpdgTunnelManager)
                     .reportIwlanError(eq(testApnName), eq(error), eq(expectedBackoffTime));
         }
-        verify(mMockIwlanTunnelCallback, atLeastOnce()).onClosed(eq(testApnName), eq(error));
+        verify(mMockIwlanTunnelCallback, atLeastOnce()).onClosed(eq(testApnName), eq(error), any());
     }
 
     private TunnelSetupRequest getBasicTunnelSetupRequest(String apnName, int apnIpProtocol) {
@@ -1354,10 +1351,6 @@ public class EpdgTunnelManagerTest {
         return bld.build();
     }
 
-    private void setVariable(Object target, String variableName, Object value) throws Exception {
-        FieldSetter.setField(target, target.getClass().getDeclaredField(variableName), value);
-    }
-
     @Test
     public void testHandleOnClosedWithEpdgConnected_True() throws Exception {
         String testApnName = "www.xyz.com";
@@ -1369,7 +1362,6 @@ public class EpdgTunnelManagerTest {
                 testApnName,
                 mMockIkeSession,
                 mMockIwlanTunnelCallback,
-                mMockIwlanTunnelMetrics,
                 mMockIpSecTunnelInterface,
                 null /* srcIpv6Addr */,
                 0 /* srcIPv6AddrPrefixLen */,
@@ -1384,8 +1376,8 @@ public class EpdgTunnelManagerTest {
         mEpdgTunnelManager.getTmIkeSessionCallback(testApnName, token).onClosed();
         mTestLooper.dispatchAll();
 
-        verify(mMockIwlanTunnelCallback, times(1)).onClosed(eq(testApnName), eq(error));
-        verify(mEpdgTunnelManager, times(1)).reportIwlanError(eq(testApnName), eq(error));
+        verify(mMockIwlanTunnelCallback).onClosed(eq(testApnName), eq(error), any());
+        verify(mEpdgTunnelManager).reportIwlanError(eq(testApnName), eq(error));
     }
 
     @Test
@@ -1399,8 +1391,7 @@ public class EpdgTunnelManagerTest {
         boolean ret =
                 mEpdgTunnelManager.bringUpTunnel(
                         getBasicTunnelSetupRequest(TEST_APN_NAME, ApnSetting.PROTOCOL_IP),
-                        mMockIwlanTunnelCallback,
-                        mMockIwlanTunnelMetrics);
+                        mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -1413,8 +1404,8 @@ public class EpdgTunnelManagerTest {
         mEpdgTunnelManager.getTmIkeSessionCallback(testApnName, DEFAULT_TOKEN).onClosed();
         mTestLooper.dispatchAll();
 
-        verify(mMockIwlanTunnelCallback, times(1)).onClosed(eq(testApnName), eq(error));
-        verify(mEpdgTunnelManager, times(1)).reportIwlanError(eq(testApnName), eq(error));
+        verify(mMockIwlanTunnelCallback).onClosed(eq(testApnName), eq(error), any());
+        verify(mEpdgTunnelManager).reportIwlanError(eq(testApnName), eq(error));
     }
 
     private void setOneTunnelOpened(String apnName) throws Exception {
@@ -1424,7 +1415,6 @@ public class EpdgTunnelManagerTest {
                 apnName,
                 mMockIkeSession,
                 mMockIwlanTunnelCallback,
-                mMockIwlanTunnelMetrics,
                 mMockIpSecTunnelInterface,
                 null /* srcIpv6Addr */,
                 0 /* srcIPv6AddrPrefixLen */,
@@ -1460,7 +1450,7 @@ public class EpdgTunnelManagerTest {
                 EXPECTED_EPDG_ADDRESSES, new IwlanError(IwlanError.NO_ERROR), 1);
         mTestLooper.dispatchAll();
 
-        verify(mMockIkeSessionCreator, times(1))
+        verify(mMockIkeSessionCreator)
                 .createIkeSession(
                         eq(mMockContext),
                         ikeSessionArgumentCaptors.mIkeSessionParamsCaptor.capture(),
@@ -1490,8 +1480,7 @@ public class EpdgTunnelManagerTest {
         boolean ret =
                 mEpdgTunnelManager.bringUpTunnel(
                         getBasicTunnelSetupRequest(apnName, ApnSetting.PROTOCOL_IP),
-                        mMockIwlanTunnelCallback,
-                        mMockIwlanTunnelMetrics);
+                        mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -1505,7 +1494,7 @@ public class EpdgTunnelManagerTest {
                         ikeSessionArgumentCaptors.mChildSessionCallbackCaptor.capture());
 
         if (!needPendingBringUpReq) {
-            verify(mMockIpSecManager, times(1))
+            verify(mMockIpSecManager)
                     .createIpSecTunnelInterface(
                             any(InetAddress.class), any(InetAddress.class), eq(network));
         }
@@ -1532,9 +1521,9 @@ public class EpdgTunnelManagerTest {
 
         childSessionCallback.onOpened(mMockChildSessionConfiguration);
         mTestLooper.dispatchAll();
-        verify(mEpdgTunnelManager, times(1))
+        verify(mEpdgTunnelManager)
                 .reportIwlanError(eq(apnName), eq(new IwlanError(IwlanError.NO_ERROR)));
-        verify(mMockIwlanTunnelCallback, times(1)).onOpened(eq(apnName), any());
+        verify(mMockIwlanTunnelCallback).onOpened(eq(apnName), any(), any());
     }
 
     @Test
@@ -1556,7 +1545,7 @@ public class EpdgTunnelManagerTest {
         ChildSessionCallback childSessionCallback =
                 ikeSessionArgumentCaptors.mChildSessionCallbackCaptor.getValue();
         verifyTunnelOnOpened(toBeOpenedApnName, childSessionCallback);
-        verify(mMockEpdgSelector, times(0)).onEpdgConnectionFailed(any());
+        verify(mMockEpdgSelector, never()).onEpdgConnectionFailed(any(), any());
         verify(mMockEpdgSelector).onEpdgConnectedSuccessfully();
     }
 
@@ -1591,7 +1580,6 @@ public class EpdgTunnelManagerTest {
                 testApnName,
                 mMockIkeSession,
                 mMockIwlanTunnelCallback,
-                mMockIwlanTunnelMetrics,
                 mMockIpSecTunnelInterface,
                 null /* srcIpv6Addr */,
                 0 /* srcIPv6AddrPrefixLen */,
@@ -1608,8 +1596,8 @@ public class EpdgTunnelManagerTest {
                 .onClosedWithException(mMockIkeException);
         mTestLooper.dispatchAll();
 
-        verify(mMockIwlanTunnelCallback, times(1)).onClosed(eq(testApnName), eq(error));
-        verify(mEpdgTunnelManager, times(1)).reportIwlanError(eq(testApnName), eq(error));
+        verify(mMockIwlanTunnelCallback).onClosed(eq(testApnName), eq(error), any());
+        verify(mEpdgTunnelManager).reportIwlanError(eq(testApnName), eq(error));
     }
 
     @Test
@@ -1622,8 +1610,7 @@ public class EpdgTunnelManagerTest {
         boolean ret =
                 mEpdgTunnelManager.bringUpTunnel(
                         getBasicTunnelSetupRequest(TEST_APN_NAME, ApnSetting.PROTOCOL_IP),
-                        mMockIwlanTunnelCallback,
-                        mMockIwlanTunnelMetrics);
+                        mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -1639,8 +1626,8 @@ public class EpdgTunnelManagerTest {
                 .onClosedWithException(mMockIkeException);
         mTestLooper.dispatchAll();
 
-        verify(mMockIwlanTunnelCallback, times(1)).onClosed(eq(testApnName), any(IwlanError.class));
-        verify(mEpdgTunnelManager, times(1)).reportIwlanError(eq(testApnName), eq(error));
+        verify(mMockIwlanTunnelCallback).onClosed(eq(testApnName), any(IwlanError.class), any());
+        verify(mEpdgTunnelManager).reportIwlanError(eq(testApnName), eq(error));
     }
 
     @Test
@@ -1653,7 +1640,6 @@ public class EpdgTunnelManagerTest {
                 testApnName,
                 mMockIkeSession,
                 mMockIwlanTunnelCallback,
-                mMockIwlanTunnelMetrics,
                 mMockIpSecTunnelInterface,
                 null /* srcIpv6Addr */,
                 0 /* srcIPv6AddrPrefixLen */,
@@ -1688,7 +1674,7 @@ public class EpdgTunnelManagerTest {
                 mMockedIpSecTransformIn, IpSecManager.DIRECTION_IN);
         mTestLooper.dispatchAll();
 
-        verify(mMockIkeSession, times(1)).close();
+        verify(mMockIkeSession).close();
     }
 
     @Test
@@ -1708,7 +1694,7 @@ public class EpdgTunnelManagerTest {
                 .onIkeSessionConnectionInfoChanged(mMockIkeSessionConnectionInfo);
         mTestLooper.dispatchAll();
 
-        verify(mMockIpSecTunnelInterface, times(1)).setUnderlyingNetwork(mMockDefaultNetwork);
+        verify(mMockIpSecTunnelInterface).setUnderlyingNetwork(mMockDefaultNetwork);
     }
 
     @Test
@@ -1729,7 +1715,7 @@ public class EpdgTunnelManagerTest {
                 .onIkeSessionConnectionInfoChanged(mMockIkeSessionConnectionInfo);
         mTestLooper.dispatchAll();
 
-        verify(mMockIpSecTunnelInterface, times(0)).setUnderlyingNetwork(any());
+        verify(mMockIpSecTunnelInterface, never()).setUnderlyingNetwork(any());
     }
 
     @Test
@@ -1763,8 +1749,6 @@ public class EpdgTunnelManagerTest {
     }
 
     private void testSetIkeTrafficSelectors(int apnProtocol, boolean handover) throws Exception {
-        String testApnName = "www.xyz.com";
-
         doReturn(null)
                 .when(mMockIkeSessionCreator)
                 .createIkeSession(
@@ -1781,14 +1765,12 @@ public class EpdgTunnelManagerTest {
             ret =
                     mEpdgTunnelManager.bringUpTunnel(
                             getHandoverTunnelSetupRequest(TEST_APN_NAME, apnProtocol),
-                            mMockIwlanTunnelCallback,
-                            mMockIwlanTunnelMetrics);
+                            mMockIwlanTunnelCallback);
         } else {
             ret =
                     mEpdgTunnelManager.bringUpTunnel(
                             getBasicTunnelSetupRequest(TEST_APN_NAME, apnProtocol),
-                            mMockIwlanTunnelCallback,
-                            mMockIwlanTunnelMetrics);
+                            mMockIwlanTunnelCallback);
         }
 
         assertTrue(ret);
@@ -1881,7 +1863,6 @@ public class EpdgTunnelManagerTest {
                 testApnName,
                 mMockIkeSession,
                 mMockIwlanTunnelCallback,
-                mMockIwlanTunnelMetrics,
                 mMockIpSecTunnelInterface,
                 null /* srcIpv6Addr */,
                 0 /* srcIPv6AddrPrefixLen */,
@@ -1898,8 +1879,8 @@ public class EpdgTunnelManagerTest {
                 .onClosedWithException(mockException);
         mTestLooper.dispatchAll();
 
-        verify(mMockIwlanTunnelCallback, times(1)).onClosed(eq(testApnName), eq(error));
-        verify(mEpdgTunnelManager, times(1)).reportIwlanError(eq(testApnName), eq(error));
+        verify(mMockIwlanTunnelCallback).onClosed(eq(testApnName), eq(error), any());
+        verify(mEpdgTunnelManager).reportIwlanError(eq(testApnName), eq(error));
     }
 
     @Test
@@ -1912,8 +1893,7 @@ public class EpdgTunnelManagerTest {
         boolean ret =
                 mEpdgTunnelManager.bringUpTunnel(
                         getBasicTunnelSetupRequest(TEST_APN_NAME, ApnSetting.PROTOCOL_IP),
-                        mMockIwlanTunnelCallback,
-                        mMockIwlanTunnelMetrics);
+                        mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -1923,7 +1903,7 @@ public class EpdgTunnelManagerTest {
         mEpdgTunnelManager.mEpdgMonitor.onApnDisconnectFromEpdg(TEST_APN_NAME);
         mEpdgTunnelManager.onConnectedToEpdg(false);
 
-        verify(mEpdgTunnelManager, times(1)).reportIwlanError(eq(testApnName), eq(error));
+        verify(mEpdgTunnelManager).reportIwlanError(eq(testApnName), eq(error));
     }
 
     @Test
@@ -1945,8 +1925,8 @@ public class EpdgTunnelManagerTest {
                 .onClosedWithException(ikeException);
         mTestLooper.dispatchAll();
         verify(mEpdgTunnelManager, never()).reportIwlanError(eq(TEST_APN_NAME), any());
-        verify(mMockIwlanTunnelCallback, times(1))
-                .onClosed(eq(TEST_APN_NAME), eq(new IwlanError(ikeException)));
+        verify(mMockIwlanTunnelCallback)
+                .onClosed(eq(TEST_APN_NAME), eq(new IwlanError(ikeException)), any());
     }
 
     @Test
@@ -1960,16 +1940,13 @@ public class EpdgTunnelManagerTest {
         boolean ret =
                 mEpdgTunnelManager.bringUpTunnel(
                         getBasicTunnelSetupRequest(TEST_APN_NAME, ApnSetting.PROTOCOL_IP),
-                        mMockIwlanTunnelCallback,
-                        mMockIwlanTunnelMetrics);
+                        mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
-        verify(mMockIwlanTunnelCallback, times(1)).onClosed(eq(testApnName), eq(error));
+        verify(mMockIwlanTunnelCallback).onClosed(eq(testApnName), eq(error), any());
     }
 
     private void verifyN1modeCapability(int pduSessionId) throws Exception {
-
-        String testApnName = "www.xyz.com";
         byte pduSessionIdToByte = (byte) pduSessionId;
 
         doReturn(null)
@@ -1988,8 +1965,7 @@ public class EpdgTunnelManagerTest {
                 mEpdgTunnelManager.bringUpTunnel(
                         getBasicTunnelSetupRequest(
                                 TEST_APN_NAME, ApnSetting.PROTOCOL_IPV6, pduSessionId),
-                        mMockIwlanTunnelCallback,
-                        mMockIwlanTunnelMetrics);
+                        mMockIwlanTunnelCallback);
 
         assertTrue(ret);
         mTestLooper.dispatchAll();
@@ -2022,8 +1998,6 @@ public class EpdgTunnelManagerTest {
 
     @Test
     public void testInvalidNattTimerFromCarrierConfig() throws Exception {
-        String testApnName = "www.xyz.com";
-
         int nattTimer = 4500; // valid range for natt timer is 0-3600
         int defaultNattTimer =
                 IwlanCarrierConfig.getDefaultConfigInt(
@@ -2045,8 +2019,7 @@ public class EpdgTunnelManagerTest {
         boolean ret =
                 mEpdgTunnelManager.bringUpTunnel(
                         getBasicTunnelSetupRequest(TEST_APN_NAME, ApnSetting.PROTOCOL_IP),
-                        mMockIwlanTunnelCallback,
-                        mMockIwlanTunnelMetrics);
+                        mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -2104,9 +2077,7 @@ public class EpdgTunnelManagerTest {
                         any(IkeSessionCallback.class),
                         any(ChildSessionCallback.class));
 
-        boolean ret =
-                mEpdgTunnelManager.bringUpTunnel(
-                        tsr, mMockIwlanTunnelCallback, mMockIwlanTunnelMetrics);
+        boolean ret = mEpdgTunnelManager.bringUpTunnel(tsr, mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -2172,23 +2143,23 @@ public class EpdgTunnelManagerTest {
         boolean ipv4ConfigRequestPresent = true;
         for (TunnelModeChildSessionParams.TunnelModeChildConfigRequest configRequest :
                 configRequests) {
-            if (configRequest instanceof TunnelModeChildSessionParams.ConfigRequestIpv6Address) {
+            if (configRequest
+                    instanceof
+                    TunnelModeChildSessionParams.ConfigRequestIpv6Address
+                                    configRequestIpv6Address) {
                 ipv6ConfigRequestPresent = true;
-                assertEquals(
-                        testAddressV6,
-                        ((TunnelModeChildSessionParams.ConfigRequestIpv6Address) configRequest)
-                                .getAddress());
+                assertEquals(testAddressV6, configRequestIpv6Address.getAddress());
                 assertEquals(
                         ipv6AddressLen,
                         ((TunnelModeChildSessionParams.ConfigRequestIpv6Address) configRequest)
                                 .getPrefixLength());
             }
-            if (configRequest instanceof TunnelModeChildSessionParams.ConfigRequestIpv4Address) {
+            if (configRequest
+                    instanceof
+                    TunnelModeChildSessionParams.ConfigRequestIpv4Address
+                                    configRequestIpv4Address) {
                 ipv4ConfigRequestPresent = true;
-                assertEquals(
-                        testAddressV4,
-                        ((TunnelModeChildSessionParams.ConfigRequestIpv4Address) configRequest)
-                                .getAddress());
+                assertEquals(testAddressV4, configRequestIpv4Address.getAddress());
             }
         }
         assertTrue(ipv6ConfigRequestPresent);
@@ -2208,8 +2179,7 @@ public class EpdgTunnelManagerTest {
         boolean ret =
                 mEpdgTunnelManager.bringUpTunnel(
                         getBasicTunnelSetupRequest(TEST_APN_NAME, ApnSetting.PROTOCOL_IP),
-                        mMockIwlanTunnelCallback,
-                        mMockIwlanTunnelMetrics);
+                        mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -2217,7 +2187,7 @@ public class EpdgTunnelManagerTest {
                 EXPECTED_EPDG_ADDRESSES, new IwlanError(IwlanError.NO_ERROR), 1);
         mTestLooper.dispatchAll();
 
-        verify(mMockIwlanTunnelCallback, times(1)).onClosed(eq(testApnName), eq(error));
+        verify(mMockIwlanTunnelCallback).onClosed(eq(testApnName), eq(error), any());
     }
 
     @Test
@@ -2235,8 +2205,7 @@ public class EpdgTunnelManagerTest {
         boolean ret =
                 mEpdgTunnelManager.bringUpTunnel(
                         getBasicTunnelSetupRequest(TEST_APN_NAME, ApnSetting.PROTOCOL_IP),
-                        mMockIwlanTunnelCallback,
-                        mMockIwlanTunnelMetrics);
+                        mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -2244,7 +2213,7 @@ public class EpdgTunnelManagerTest {
                 EXPECTED_EPDG_ADDRESSES, new IwlanError(IwlanError.NO_ERROR), 1);
         mTestLooper.dispatchAll();
 
-        verify(mMockIwlanTunnelCallback, times(1)).onClosed(eq(testApnName), eq(error));
+        verify(mMockIwlanTunnelCallback).onClosed(eq(testApnName), eq(error), any());
     }
 
     @Test
@@ -2254,8 +2223,7 @@ public class EpdgTunnelManagerTest {
         boolean ret =
                 mEpdgTunnelManager.bringUpTunnel(
                         getBasicTunnelSetupRequest(TEST_APN_NAME, ApnSetting.PROTOCOL_IP),
-                        mMockIwlanTunnelCallback,
-                        mMockIwlanTunnelMetrics);
+                        mMockIwlanTunnelCallback);
         assertTrue(ret);
 
         // close tunnel when ePDG selection is incomplete
@@ -2263,15 +2231,16 @@ public class EpdgTunnelManagerTest {
                 TEST_APN_NAME,
                 false /*forceClose*/,
                 mMockIwlanTunnelCallback,
-                mMockIwlanTunnelMetrics,
                 BRINGDOWN_REASON_UNKNOWN);
         mTestLooper.dispatchAll();
 
-        verify(mMockIwlanTunnelCallback, times(1))
-                .onClosed(eq(TEST_APN_NAME), eq(new IwlanError(IwlanError.NO_ERROR)));
         ArgumentCaptor<OnClosedMetrics> metricsCaptor =
                 ArgumentCaptor.forClass(OnClosedMetrics.class);
-        verify(mMockIwlanTunnelMetrics, times(1)).onClosed(metricsCaptor.capture());
+        verify(mMockIwlanTunnelCallback)
+                .onClosed(
+                        eq(TEST_APN_NAME),
+                        eq(new IwlanError(IwlanError.NO_ERROR)),
+                        metricsCaptor.capture());
         assertEquals(TEST_APN_NAME, metricsCaptor.getValue().getApnName());
         assertNull(metricsCaptor.getValue().getEpdgServerAddress());
     }
@@ -2291,7 +2260,7 @@ public class EpdgTunnelManagerTest {
                 .getTmIkeSessionCallback(TEST_APN_NAME, 0 /* token */)
                 .onClosedWithException(mMockIkeException);
         mTestLooper.dispatchAll();
-        verify(mMockIwlanTunnelCallback, times(1)).onClosed(eq(TEST_APN_NAME), eq(error));
+        verify(mMockIwlanTunnelCallback).onClosed(eq(TEST_APN_NAME), eq(error), any());
         assertNull(mEpdgTunnelManager.getTunnelConfigForApn(TEST_APN_NAME));
 
         // testApnName1 with token 1
@@ -2304,7 +2273,7 @@ public class EpdgTunnelManagerTest {
                 .getTmIkeSessionCallback(TEST_APN_NAME, 0 /* token */)
                 .onClosedWithException(mMockIkeException);
         mTestLooper.dispatchAll();
-        verify(mMockIwlanTunnelCallback, never()).onClosed(eq(TEST_APN_NAME), eq(error));
+        verify(mMockIwlanTunnelCallback, never()).onClosed(eq(TEST_APN_NAME), eq(error), any());
         assertNotNull(mEpdgTunnelManager.getTunnelConfigForApn(TEST_APN_NAME));
 
         // signals from active callback
@@ -2312,7 +2281,7 @@ public class EpdgTunnelManagerTest {
                 .getTmIkeSessionCallback(TEST_APN_NAME, 1 /* token */)
                 .onClosedWithException(mMockIkeException);
         mTestLooper.dispatchAll();
-        verify(mMockIwlanTunnelCallback, times(1)).onClosed(eq(TEST_APN_NAME), eq(error));
+        verify(mMockIwlanTunnelCallback).onClosed(eq(TEST_APN_NAME), eq(error), any());
         assertNull(mEpdgTunnelManager.getTunnelConfigForApn(TEST_APN_NAME));
     }
 
@@ -2324,9 +2293,7 @@ public class EpdgTunnelManagerTest {
                 CarrierConfigManager.Iwlan.KEY_EPDG_ADDRESS_IP_TYPE_PREFERENCE_INT,
                 CarrierConfigManager.Iwlan.EPDG_ADDRESS_IPV4_PREFERRED);
 
-        boolean ret =
-                mEpdgTunnelManager.bringUpTunnel(
-                        TSR, mMockIwlanTunnelCallback, mMockIwlanTunnelMetrics);
+        boolean ret = mEpdgTunnelManager.bringUpTunnel(TSR, mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -2349,9 +2316,7 @@ public class EpdgTunnelManagerTest {
                 CarrierConfigManager.Iwlan.KEY_EPDG_ADDRESS_IP_TYPE_PREFERENCE_INT,
                 CarrierConfigManager.Iwlan.EPDG_ADDRESS_IPV6_PREFERRED);
 
-        boolean ret =
-                mEpdgTunnelManager.bringUpTunnel(
-                        TSR, mMockIwlanTunnelCallback, mMockIwlanTunnelMetrics);
+        boolean ret = mEpdgTunnelManager.bringUpTunnel(TSR, mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -2374,9 +2339,7 @@ public class EpdgTunnelManagerTest {
                 CarrierConfigManager.Iwlan.KEY_EPDG_ADDRESS_IP_TYPE_PREFERENCE_INT,
                 CarrierConfigManager.Iwlan.EPDG_ADDRESS_IPV4_ONLY);
 
-        boolean ret =
-                mEpdgTunnelManager.bringUpTunnel(
-                        TSR, mMockIwlanTunnelCallback, mMockIwlanTunnelMetrics);
+        boolean ret = mEpdgTunnelManager.bringUpTunnel(TSR, mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -2403,9 +2366,7 @@ public class EpdgTunnelManagerTest {
                 CarrierConfigManager.Iwlan.KEY_EPDG_ADDRESS_IP_TYPE_PREFERENCE_INT,
                 CarrierConfigManager.Iwlan.EPDG_ADDRESS_IPV6_ONLY);
 
-        boolean ret =
-                mEpdgTunnelManager.bringUpTunnel(
-                        TSR, mMockIwlanTunnelCallback, mMockIwlanTunnelMetrics);
+        boolean ret = mEpdgTunnelManager.bringUpTunnel(TSR, mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -2431,9 +2392,7 @@ public class EpdgTunnelManagerTest {
                 CarrierConfigManager.Iwlan.KEY_EPDG_ADDRESS_IP_TYPE_PREFERENCE_INT,
                 CarrierConfigManager.Iwlan.EPDG_ADDRESS_IPV6_ONLY);
 
-        boolean ret =
-                mEpdgTunnelManager.bringUpTunnel(
-                        TSR, mMockIwlanTunnelCallback, mMockIwlanTunnelMetrics);
+        boolean ret = mEpdgTunnelManager.bringUpTunnel(TSR, mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -2446,8 +2405,8 @@ public class EpdgTunnelManagerTest {
                         eq(false),
                         eq(mMockDefaultNetwork),
                         any());
-        verify(mEpdgTunnelManager, times(1)).reportIwlanError(eq(TEST_APN_NAME), eq(error));
-        verify(mMockIwlanTunnelCallback, times(1)).onClosed(eq(TEST_APN_NAME), eq(error));
+        verify(mEpdgTunnelManager).reportIwlanError(eq(TEST_APN_NAME), eq(error));
+        verify(mMockIwlanTunnelCallback).onClosed(eq(TEST_APN_NAME), eq(error), any());
     }
 
     @Test
@@ -2458,9 +2417,7 @@ public class EpdgTunnelManagerTest {
                 CarrierConfigManager.Iwlan.KEY_EPDG_ADDRESS_IP_TYPE_PREFERENCE_INT,
                 CarrierConfigManager.Iwlan.EPDG_ADDRESS_SYSTEM_PREFERRED);
 
-        boolean ret =
-                mEpdgTunnelManager.bringUpTunnel(
-                        TSR, mMockIwlanTunnelCallback, mMockIwlanTunnelMetrics);
+        boolean ret = mEpdgTunnelManager.bringUpTunnel(TSR, mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -2475,25 +2432,6 @@ public class EpdgTunnelManagerTest {
                         any());
     }
 
-    @Test
-    public void testOnOpenedTunnelMetricsData() throws Exception {
-        mEpdgTunnelManager.bringUpTunnel(
-                getBasicTunnelSetupRequest(TEST_APN_NAME, ApnSetting.PROTOCOL_IP),
-                mMockIwlanTunnelCallback,
-                mMockIwlanTunnelMetrics);
-        IkeSessionArgumentCaptors ikeSessionArgumentCaptors =
-                verifyBringUpTunnelWithDnsQuery(TEST_APN_NAME, mMockDefaultNetwork);
-        ChildSessionCallback childSessionCallback =
-                ikeSessionArgumentCaptors.mChildSessionCallbackCaptor.getValue();
-        verifyTunnelOnOpened(TEST_APN_NAME, childSessionCallback);
-        mTestLooper.dispatchAll();
-
-        ArgumentCaptor<OnOpenedMetrics> metricsCaptor =
-                ArgumentCaptor.forClass(OnOpenedMetrics.class);
-        verify(mMockIwlanTunnelMetrics, times(1)).onOpened(metricsCaptor.capture());
-        assertEquals(TEST_APN_NAME, metricsCaptor.getValue().getApnName());
-    }
-
     @Test
     public void testCloseTunnelWithIkeInitTimeout() throws Exception {
         String testApnName = "www.xyz.com";
@@ -2515,10 +2453,12 @@ public class EpdgTunnelManagerTest {
         ikeSessionCallbackCaptor.getValue().onClosedWithException(mMockIkeIoException);
         mTestLooper.dispatchAll();
 
-        verify(mEpdgTunnelManager, times(1)).reportIwlanError(eq(testApnName), eq(error));
-        verify(mMockEpdgSelector).onEpdgConnectionFailed(eq(EXPECTED_EPDG_ADDRESSES.get(0)));
-        verify(mMockEpdgSelector, times(0)).onEpdgConnectedSuccessfully();
-        verify(mMockIwlanTunnelCallback, atLeastOnce()).onClosed(eq(testApnName), eq(error));
+        verify(mEpdgTunnelManager).reportIwlanError(eq(testApnName), eq(error));
+        verify(mMockEpdgSelector)
+                .onEpdgConnectionFailed(
+                        eq(EXPECTED_EPDG_ADDRESSES.get(0)), any(IkeIOException.class));
+        verify(mMockEpdgSelector, never()).onEpdgConnectedSuccessfully();
+        verify(mMockIwlanTunnelCallback, atLeastOnce()).onClosed(eq(testApnName), eq(error), any());
     }
 
     @Test
@@ -2537,7 +2477,7 @@ public class EpdgTunnelManagerTest {
         mTestLooper.dispatchAll();
 
         verify(mEpdgTunnelManager, never()).reportIwlanError(eq(TEST_APN_NAME), eq(error));
-        verify(mMockIwlanTunnelCallback, times(1)).onClosed(eq(TEST_APN_NAME), eq(error));
+        verify(mMockIwlanTunnelCallback).onClosed(eq(TEST_APN_NAME), eq(error), any());
     }
 
     @Test
@@ -2561,9 +2501,9 @@ public class EpdgTunnelManagerTest {
                 .onClosedWithException(mMockIkeIoException);
         mTestLooper.dispatchAll();
 
-        verify(mMockIkeSession, times(1)).setNetwork(eq(newNetwork));
+        verify(mMockIkeSession).setNetwork(eq(newNetwork));
         verify(mEpdgTunnelManager, never()).reportIwlanError(eq(TEST_APN_NAME), eq(error));
-        verify(mMockIwlanTunnelCallback, times(1)).onClosed(eq(TEST_APN_NAME), eq(error));
+        verify(mMockIwlanTunnelCallback).onClosed(eq(TEST_APN_NAME), eq(error), any());
     }
 
     @Test
@@ -2584,7 +2524,7 @@ public class EpdgTunnelManagerTest {
         Network newNetwork = mock(Network.class);
         mEpdgTunnelManager.updateNetwork(newNetwork, mMockLinkProperties);
         mTestLooper.dispatchAll();
-        verify(mMockIkeSession, times(1)).setNetwork(eq(newNetwork));
+        verify(mMockIkeSession).setNetwork(eq(newNetwork));
     }
 
     @Test
@@ -2603,7 +2543,7 @@ public class EpdgTunnelManagerTest {
                 mMockedIpSecTransformIn, IpSecManager.DIRECTION_IN);
         mTestLooper.dispatchAll();
 
-        verify(mMockEpdgSelector, times(1))
+        verify(mMockEpdgSelector)
                 .getValidatedServerList(
                         anyInt(), /* transactionId */
                         anyInt(), /* filter */
@@ -2645,10 +2585,9 @@ public class EpdgTunnelManagerTest {
 
         mEpdgTunnelManager.bringUpTunnel(
                 getBasicTunnelSetupRequest(apnName, ApnSetting.PROTOCOL_IP),
-                mMockIwlanTunnelCallback,
-                mMockIwlanTunnelMetrics);
+                mMockIwlanTunnelCallback);
         mTestLooper.dispatchAll();
-        verify(mMockIwlanTunnelCallback, times(1)).onClosed(eq(apnName), any(IwlanError.class));
+        verify(mMockIwlanTunnelCallback).onClosed(eq(apnName), any(IwlanError.class), any());
     }
 
     @Test
@@ -2675,7 +2614,7 @@ public class EpdgTunnelManagerTest {
 
         mEpdgTunnelManager.updateNetwork(newNetwork, mMockLinkProperties);
         mTestLooper.dispatchAll();
-        verify(mMockIkeSession, times(1)).setNetwork(eq(newNetwork));
+        verify(mMockIkeSession).setNetwork(eq(newNetwork));
     }
 
     @Test
@@ -2685,7 +2624,6 @@ public class EpdgTunnelManagerTest {
                 testApnName,
                 mMockIkeSession,
                 mMockIwlanTunnelCallback,
-                mMockIwlanTunnelMetrics,
                 mMockIpSecTunnelInterface,
                 null /* srcIpv6Addr */,
                 0 /* srcIPv6AddrPrefixLen */,
@@ -2695,7 +2633,7 @@ public class EpdgTunnelManagerTest {
 
         mEpdgTunnelManager.requestNetworkValidationForApn(testApnName);
         mTestLooper.dispatchAll();
-        verify(mMockIkeSession, times(1)).requestLivenessCheck();
+        verify(mMockIkeSession).requestLivenessCheck();
 
         int[][] orderedUpdateEvents = {
             {
@@ -2736,7 +2674,6 @@ public class EpdgTunnelManagerTest {
                 testApnName,
                 mMockIkeSession,
                 mMockIwlanTunnelCallback,
-                mMockIwlanTunnelMetrics,
                 mMockIpSecTunnelInterface,
                 null /* srcIpv6Addr */,
                 0 /* srcIPv6AddrPrefixLen */,
@@ -2745,7 +2682,7 @@ public class EpdgTunnelManagerTest {
 
         mEpdgTunnelManager.requestNetworkValidationForApn(testApnName);
         mTestLooper.dispatchAll();
-        verify(mMockIkeSession, times(1)).requestLivenessCheck();
+        verify(mMockIkeSession).requestLivenessCheck();
 
         int[][] orderedUpdateEvents = {
             {
@@ -2787,7 +2724,6 @@ public class EpdgTunnelManagerTest {
                 testApnName,
                 mMockIkeSession,
                 mMockIwlanTunnelCallback,
-                mMockIwlanTunnelMetrics,
                 mMockIpSecTunnelInterface,
                 null /* srcIpv6Addr */,
                 0 /* srcIPv6AddrPrefixLen */,
@@ -2834,7 +2770,6 @@ public class EpdgTunnelManagerTest {
                 testApnName,
                 mMockIkeSession,
                 mMockIwlanTunnelCallback,
-                mMockIwlanTunnelMetrics,
                 mMockIpSecTunnelInterface,
                 null /* srcIpv6Addr */,
                 0 /* srcIPv6AddrPrefixLen */,
@@ -2847,7 +2782,7 @@ public class EpdgTunnelManagerTest {
                 .getTmIkeSessionCallback(testApnName, token)
                 .onLivenessStatusChanged(unknown_liveness_status);
         mTestLooper.dispatchAll();
-        verify(mMockIwlanTunnelCallback, times(1))
+        verify(mMockIwlanTunnelCallback)
                 .onNetworkValidationStatusChanged(
                         eq(testApnName), eq(PreciseDataConnectionState.NETWORK_VALIDATION_SUCCESS));
     }
@@ -2877,7 +2812,6 @@ public class EpdgTunnelManagerTest {
                 apnName,
                 mMockIkeSession,
                 mMockIwlanTunnelCallback,
-                mMockIwlanTunnelMetrics,
                 mMockIpSecTunnelInterface,
                 null /* srcIPv6Addr */,
                 0 /* srcIPv6AddrPrefixLen */,
@@ -2904,8 +2838,7 @@ public class EpdgTunnelManagerTest {
         boolean ret =
                 mEpdgTunnelManager.bringUpTunnel(
                         getBasicEmergencyTunnelSetupRequest(testEmergencyApnName),
-                        mMockIwlanTunnelCallback,
-                        mMockIwlanTunnelMetrics);
+                        mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -2952,8 +2885,7 @@ public class EpdgTunnelManagerTest {
         boolean ret =
                 mEpdgTunnelManager.bringUpTunnel(
                         getBasicEmergencyTunnelSetupRequest(testEmergencyApnName),
-                        mMockIwlanTunnelCallback,
-                        mMockIwlanTunnelMetrics);
+                        mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -2977,8 +2909,7 @@ public class EpdgTunnelManagerTest {
         ret =
                 mEpdgTunnelManager.bringUpTunnel(
                         getBasicEmergencyTunnelSetupRequest(testEmergencyApnName),
-                        mMockIwlanTunnelCallback,
-                        mMockIwlanTunnelMetrics);
+                        mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -3036,8 +2967,7 @@ public class EpdgTunnelManagerTest {
         boolean ret =
                 mEpdgTunnelManager.bringUpTunnel(
                         getBasicTunnelSetupRequest(testMmsApnName, ApnSetting.PROTOCOL_IP),
-                        mMockIwlanTunnelCallback,
-                        mMockIwlanTunnelMetrics);
+                        mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -3077,8 +3007,7 @@ public class EpdgTunnelManagerTest {
         boolean ret =
                 mEpdgTunnelManager.bringUpTunnel(
                         getBasicTunnelSetupRequest(testImsApnName, ApnSetting.PROTOCOL_IP),
-                        mMockIwlanTunnelCallback,
-                        mMockIwlanTunnelMetrics);
+                        mMockIwlanTunnelCallback);
         assertTrue(ret);
         mTestLooper.dispatchAll();
 
@@ -3095,4 +3024,413 @@ public class EpdgTunnelManagerTest {
         IkeSessionParams ikeSessionParams = ikeSessionParamsCaptor.getValue();
         assertEquals(SEPARATE_EPDG_ADDRESS_FOR_EMERGENCY, ikeSessionParams.getServerHostname());
     }
+
+    @Test
+    public void testUnderlyingNetworkValidation_IkeInitTimeout() throws Exception {
+        when(mMockNetworkCapabilities.hasCapability(
+                        eq(NetworkCapabilities.NET_CAPABILITY_VALIDATED)))
+                .thenReturn(true);
+        IwlanCarrierConfig.putTestConfigIntArray(
+                IwlanCarrierConfig.KEY_UNDERLYING_NETWORK_VALIDATION_EVENTS_INT_ARRAY,
+                new int[] {IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_NO_RESPONSE});
+
+        advanceClockByTimeMs(100000);
+        setupTunnelBringup();
+        ArgumentCaptor<EpdgTunnelManager.TmIkeSessionCallback> ikeSessionCallbackCaptor =
+                ArgumentCaptor.forClass(EpdgTunnelManager.TmIkeSessionCallback.class);
+        verify(mMockIkeSessionCreator, atLeastOnce())
+                .createIkeSession(
+                        eq(mMockContext),
+                        any(IkeSessionParams.class),
+                        any(ChildSessionParams.class),
+                        any(Executor.class),
+                        ikeSessionCallbackCaptor.capture(),
+                        any(ChildSessionCallback.class));
+        ikeSessionCallbackCaptor.getValue().onClosedWithException(mMockIkeIoException);
+        mTestLooper.dispatchAll();
+
+        verify(mMockConnectivityManager)
+                .reportNetworkConnectivity(eq(mMockDefaultNetwork), eq(false));
+    }
+
+    @Test
+    public void testUnderlyingNetworkValidation_IkeDpdTimeout() throws Exception {
+        when(mMockNetworkCapabilities.hasCapability(
+                        eq(NetworkCapabilities.NET_CAPABILITY_VALIDATED)))
+                .thenReturn(true);
+        IwlanCarrierConfig.putTestConfigIntArray(
+                IwlanCarrierConfig.KEY_UNDERLYING_NETWORK_VALIDATION_EVENTS_INT_ARRAY,
+                new int[] {IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_NO_RESPONSE});
+
+        advanceClockByTimeMs(100000);
+        IkeSessionArgumentCaptors ikeSessionArgumentCaptors =
+                verifyBringUpTunnelWithDnsQuery(TEST_APN_NAME, mMockDefaultNetwork);
+        ChildSessionCallback childSessionCallback =
+                ikeSessionArgumentCaptors.mChildSessionCallbackCaptor.getValue();
+        verifyTunnelOnOpened(TEST_APN_NAME, childSessionCallback);
+        mEpdgTunnelManager
+                .getTmIkeSessionCallback(
+                        TEST_APN_NAME, mEpdgTunnelManager.getCurrentTokenForApn(TEST_APN_NAME))
+                .onClosedWithException(mMockIkeIoException);
+        mTestLooper.dispatchAll();
+
+        verify(mMockConnectivityManager)
+                .reportNetworkConnectivity(eq(mMockDefaultNetwork), eq(false));
+    }
+
+    @Test
+    public void testUnderlyingNetworkValidation_IkeMobilityTimeout() throws Exception {
+        when(mMockNetworkCapabilities.hasCapability(
+                        eq(NetworkCapabilities.NET_CAPABILITY_VALIDATED)))
+                .thenReturn(true);
+        IwlanCarrierConfig.putTestConfigIntArray(
+                IwlanCarrierConfig.KEY_UNDERLYING_NETWORK_VALIDATION_EVENTS_INT_ARRAY,
+                new int[] {IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_NO_RESPONSE});
+
+        advanceClockByTimeMs(100000);
+        IkeSessionArgumentCaptors ikeSessionArgumentCaptors =
+                verifyBringUpTunnelWithDnsQuery(
+                        TEST_APN_NAME, mMockDefaultNetwork, mMockIkeSession);
+        ChildSessionCallback childSessionCallback =
+                ikeSessionArgumentCaptors.mChildSessionCallbackCaptor.getValue();
+        verifyTunnelOnOpened(TEST_APN_NAME, childSessionCallback);
+
+        Network newNetwork = mock(Network.class);
+        mEpdgTunnelManager.updateNetwork(newNetwork, mMockLinkProperties);
+        mTestLooper.dispatchAll();
+
+        mEpdgTunnelManager
+                .getTmIkeSessionCallback(
+                        TEST_APN_NAME, mEpdgTunnelManager.getCurrentTokenForApn(TEST_APN_NAME))
+                .onClosedWithException(mMockIkeIoException);
+        mTestLooper.dispatchAll();
+
+        verify(mMockConnectivityManager).reportNetworkConnectivity(eq(newNetwork), eq(false));
+    }
+
+    @Test
+    public void testUnderlyingNetworkValidation_DnsResolutionFailure() {
+        IwlanError error = new IwlanError(IwlanError.EPDG_SELECTOR_SERVER_SELECTION_FAILED);
+        when(mMockNetworkCapabilities.hasCapability(
+                        eq(NetworkCapabilities.NET_CAPABILITY_VALIDATED)))
+                .thenReturn(true);
+        IwlanCarrierConfig.putTestConfigIntArray(
+                IwlanCarrierConfig.KEY_UNDERLYING_NETWORK_VALIDATION_EVENTS_INT_ARRAY,
+                new int[] {IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_NO_RESPONSE});
+
+        advanceClockByTimeMs(100000);
+        boolean ret =
+                mEpdgTunnelManager.bringUpTunnel(
+                        getBasicTunnelSetupRequest(TEST_APN_NAME, ApnSetting.PROTOCOL_IP),
+                        mMockIwlanTunnelCallback);
+        assertTrue(ret);
+        mTestLooper.dispatchAll();
+
+        mEpdgTunnelManager.sendSelectionRequestComplete(null, error, 1);
+        mTestLooper.dispatchAll();
+
+        mEpdgTunnelManager.mEpdgMonitor.onApnDisconnectFromEpdg(TEST_APN_NAME);
+        mEpdgTunnelManager.onConnectedToEpdg(false);
+
+        verify(mMockConnectivityManager)
+                .reportNetworkConnectivity(eq(mMockDefaultNetwork), eq(false));
+    }
+
+    @Test
+    public void testUnderlyingNetworkValidation_IkeNetworkLostException() throws Exception {
+        when(mMockNetworkCapabilities.hasCapability(
+                        eq(NetworkCapabilities.NET_CAPABILITY_VALIDATED)))
+                .thenReturn(true);
+        IwlanCarrierConfig.putTestConfigIntArray(
+                IwlanCarrierConfig.KEY_UNDERLYING_NETWORK_VALIDATION_EVENTS_INT_ARRAY,
+                new int[] {IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_NO_RESPONSE});
+
+        advanceClockByTimeMs(100000);
+        setupTunnelBringup();
+        ArgumentCaptor<EpdgTunnelManager.TmIkeSessionCallback> ikeSessionCallbackCaptor =
+                ArgumentCaptor.forClass(EpdgTunnelManager.TmIkeSessionCallback.class);
+        verify(mMockIkeSessionCreator, atLeastOnce())
+                .createIkeSession(
+                        eq(mMockContext),
+                        any(IkeSessionParams.class),
+                        any(ChildSessionParams.class),
+                        any(Executor.class),
+                        ikeSessionCallbackCaptor.capture(),
+                        any(ChildSessionCallback.class));
+        ikeSessionCallbackCaptor
+                .getValue()
+                .onClosedWithException(new IkeNetworkLostException(mMockDefaultNetwork));
+        mTestLooper.dispatchAll();
+
+        verify(mMockConnectivityManager)
+                .reportNetworkConnectivity(eq(mMockDefaultNetwork), eq(false));
+    }
+
+    @Test
+    public void testUnderlyingNetworkValidation_UnvalidatedNetwork() throws Exception {
+        when(mMockNetworkCapabilities.hasCapability(
+                        eq(NetworkCapabilities.NET_CAPABILITY_VALIDATED)))
+                .thenReturn(false);
+        IwlanCarrierConfig.putTestConfigIntArray(
+                IwlanCarrierConfig.KEY_UNDERLYING_NETWORK_VALIDATION_EVENTS_INT_ARRAY,
+                new int[] {IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_NO_RESPONSE});
+
+        advanceClockByTimeMs(100000);
+        IkeSessionArgumentCaptors ikeSessionArgumentCaptors =
+                verifyBringUpTunnelWithDnsQuery(TEST_APN_NAME, mMockDefaultNetwork);
+        ChildSessionCallback childSessionCallback =
+                ikeSessionArgumentCaptors.mChildSessionCallbackCaptor.getValue();
+        verifyTunnelOnOpened(TEST_APN_NAME, childSessionCallback);
+        mEpdgTunnelManager
+                .getTmIkeSessionCallback(
+                        TEST_APN_NAME, mEpdgTunnelManager.getCurrentTokenForApn(TEST_APN_NAME))
+                .onClosedWithException(mMockIkeIoException);
+        mTestLooper.dispatchAll();
+
+        verify(mMockConnectivityManager, never())
+                .reportNetworkConnectivity(eq(mMockDefaultNetwork), eq(false));
+    }
+
+    @Test
+    public void testUnderlyingNetworkValidation_ConfigDisabled() throws Exception {
+        when(mMockNetworkCapabilities.hasCapability(
+                        eq(NetworkCapabilities.NET_CAPABILITY_VALIDATED)))
+                .thenReturn(true);
+        IwlanCarrierConfig.putTestConfigIntArray(
+                IwlanCarrierConfig.KEY_UNDERLYING_NETWORK_VALIDATION_EVENTS_INT_ARRAY,
+                new int[] {});
+
+        advanceClockByTimeMs(100000);
+        IkeSessionArgumentCaptors ikeSessionArgumentCaptors =
+                verifyBringUpTunnelWithDnsQuery(TEST_APN_NAME, mMockDefaultNetwork);
+        ChildSessionCallback childSessionCallback =
+                ikeSessionArgumentCaptors.mChildSessionCallbackCaptor.getValue();
+        verifyTunnelOnOpened(TEST_APN_NAME, childSessionCallback);
+        mEpdgTunnelManager
+                .getTmIkeSessionCallback(
+                        TEST_APN_NAME, mEpdgTunnelManager.getCurrentTokenForApn(TEST_APN_NAME))
+                .onClosedWithException(mMockIkeIoException);
+        mTestLooper.dispatchAll();
+
+        verify(mMockConnectivityManager, never())
+                .reportNetworkConnectivity(eq(mMockDefaultNetwork), eq(false));
+    }
+
+    @Test
+    public void testMakingCallNetworkValidation_shouldValidate_ifInEventsConfig() {
+        when(mMockNetworkCapabilities.hasCapability(
+                        eq(NetworkCapabilities.NET_CAPABILITY_VALIDATED)))
+                .thenReturn(true);
+        IwlanCarrierConfig.putTestConfigIntArray(
+                IwlanCarrierConfig.KEY_UNDERLYING_NETWORK_VALIDATION_EVENTS_INT_ARRAY,
+                new int[] {IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_MAKING_CALL});
+
+        advanceClockByTimeMs(100000);
+        mEpdgTunnelManager.validateUnderlyingNetwork(
+                IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_MAKING_CALL);
+        mTestLooper.dispatchAll();
+
+        verify(mMockConnectivityManager, times(1))
+                .reportNetworkConnectivity(eq(mMockDefaultNetwork), eq(false));
+    }
+
+    @Test
+    public void testMakingCallNetworkValidation_shouldNotValidate_ifNotInEventsConfig() {
+        when(mMockNetworkCapabilities.hasCapability(
+                        eq(NetworkCapabilities.NET_CAPABILITY_VALIDATED)))
+                .thenReturn(true);
+        IwlanCarrierConfig.putTestConfigIntArray(
+                IwlanCarrierConfig.KEY_UNDERLYING_NETWORK_VALIDATION_EVENTS_INT_ARRAY,
+                new int[] {});
+
+        advanceClockByTimeMs(100000);
+        mEpdgTunnelManager.validateUnderlyingNetwork(
+                IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_MAKING_CALL);
+        mTestLooper.dispatchAll();
+
+        verify(mMockConnectivityManager, never()).reportNetworkConnectivity(any(), eq(false));
+    }
+
+    @Test
+    public void testScreenOnNetworkValidation_shouldValidate_ifInEventsConfig() {
+        when(mMockNetworkCapabilities.hasCapability(
+                        eq(NetworkCapabilities.NET_CAPABILITY_VALIDATED)))
+                .thenReturn(true);
+        IwlanCarrierConfig.putTestConfigIntArray(
+                IwlanCarrierConfig.KEY_UNDERLYING_NETWORK_VALIDATION_EVENTS_INT_ARRAY,
+                new int[] {IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_SCREEN_ON});
+
+        advanceClockByTimeMs(100000);
+        mEpdgTunnelManager.validateUnderlyingNetwork(
+                IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_SCREEN_ON);
+        mTestLooper.dispatchAll();
+
+        verify(mMockConnectivityManager, times(1))
+                .reportNetworkConnectivity(eq(mMockDefaultNetwork), eq(false));
+    }
+
+    @Test
+    public void testScreenOnNetworkValidation_shouldNotValidate_ifNotInEventsConfig() {
+        when(mMockNetworkCapabilities.hasCapability(
+                        eq(NetworkCapabilities.NET_CAPABILITY_VALIDATED)))
+                .thenReturn(true);
+        IwlanCarrierConfig.putTestConfigIntArray(
+                IwlanCarrierConfig.KEY_UNDERLYING_NETWORK_VALIDATION_EVENTS_INT_ARRAY,
+                new int[] {});
+
+        advanceClockByTimeMs(100000);
+        mEpdgTunnelManager.validateUnderlyingNetwork(
+                IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_SCREEN_ON);
+        mTestLooper.dispatchAll();
+
+        verify(mMockConnectivityManager, never()).reportNetworkConnectivity(any(), eq(false));
+    }
+
+    @Test
+    public void testNetworkValidation_shouldNotValidate_ifWithinInterval() {
+        when(mMockNetworkCapabilities.hasCapability(
+                        eq(NetworkCapabilities.NET_CAPABILITY_VALIDATED)))
+                .thenReturn(true);
+        IwlanCarrierConfig.putTestConfigIntArray(
+                IwlanCarrierConfig.KEY_UNDERLYING_NETWORK_VALIDATION_EVENTS_INT_ARRAY,
+                new int[] {
+                    IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_MAKING_CALL,
+                    IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_SCREEN_ON
+                });
+
+        advanceClockByTimeMs(100000);
+        mEpdgTunnelManager.validateUnderlyingNetwork(
+                IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_MAKING_CALL);
+        mTestLooper.dispatchAll();
+        verify(mMockConnectivityManager, times(1))
+                .reportNetworkConnectivity(eq(mMockDefaultNetwork), eq(false));
+
+        advanceClockByTimeMs(1000);
+        // Since last validation passed 1s, but interval is 10s, should not trigger validation
+        mEpdgTunnelManager.validateUnderlyingNetwork(
+                IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_MAKING_CALL);
+        // Different validation event validation interval are shared, should not trigger validation
+        mEpdgTunnelManager.validateUnderlyingNetwork(
+                IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_SCREEN_ON);
+        mTestLooper.dispatchAll();
+        verify(mMockConnectivityManager, times(1))
+                .reportNetworkConnectivity(eq(mMockDefaultNetwork), eq(false));
+
+        advanceClockByTimeMs(20000);
+        // Since last validation passed 20s, >= interval 10s, should trigger validation
+        mEpdgTunnelManager.validateUnderlyingNetwork(
+                IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_MAKING_CALL);
+        mTestLooper.dispatchAll();
+        verify(mMockConnectivityManager, times(2))
+                .reportNetworkConnectivity(eq(mMockDefaultNetwork), eq(false));
+    }
+
+    private void verifyValidationMetricsAtom(
+            MetricsAtom metricsAtom,
+            int triggerReason,
+            int validationResult,
+            int transportType,
+            int duration) {
+        assertEquals(
+                IwlanStatsLog.IWLAN_UNDERLYING_NETWORK_VALIDATION_RESULT_REPORTED,
+                metricsAtom.getMessageId());
+        assertEquals(triggerReason, metricsAtom.getTriggerReason());
+        assertEquals(validationResult, metricsAtom.getValidationResult());
+        assertEquals(transportType, metricsAtom.getValidationTransportType());
+        assertEquals(duration, metricsAtom.getValidationDurationMills());
+    }
+
+    private ConnectivityReport createConnectivityReport(Network network, int validationResult) {
+        PersistableBundle bundle = new PersistableBundle();
+        bundle.putInt(ConnectivityReport.KEY_NETWORK_VALIDATION_RESULT, validationResult);
+        return new ConnectivityReport(
+                network, /* reportTimestamp */
+                0,
+                new LinkProperties(),
+                new NetworkCapabilities(),
+                bundle);
+    }
+
+    @Test
+    public void testReportValidationMetricsAtom_Validated() {
+        ConnectivityDiagnosticsManager.ConnectivityDiagnosticsCallback callback =
+                mConnectivityDiagnosticsCallbackArgumentCaptor.getValue();
+        when(mMockNetworkCapabilities.hasCapability(
+                        eq(NetworkCapabilities.NET_CAPABILITY_VALIDATED)))
+                .thenReturn(true);
+        when(mMockNetworkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI))
+                .thenReturn(true);
+        IwlanCarrierConfig.putTestConfigIntArray(
+                IwlanCarrierConfig.KEY_UNDERLYING_NETWORK_VALIDATION_EVENTS_INT_ARRAY,
+                new int[] {
+                    IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_MAKING_CALL,
+                    IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_SCREEN_ON
+                });
+
+        advanceClockByTimeMs(100000);
+        mEpdgTunnelManager.validateUnderlyingNetwork(
+                IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_MAKING_CALL);
+        mTestLooper.dispatchAll();
+        verify(mMockConnectivityManager, times(1))
+                .reportNetworkConnectivity(eq(mMockDefaultNetwork), eq(false));
+
+        MetricsAtom metricsAtom = mEpdgTunnelManager.getValidationMetricsAtom(mMockDefaultNetwork);
+        advanceClockByTimeMs(1000);
+        callback.onConnectivityReportAvailable(
+                createConnectivityReport(
+                        mMockDefaultNetwork, ConnectivityReport.NETWORK_VALIDATION_RESULT_VALID));
+
+        verifyValidationMetricsAtom(
+                metricsAtom,
+                NETWORK_VALIDATION_EVENT_MAKING_CALL,
+                NETWORK_VALIDATION_RESULT_VALID,
+                NETWORK_VALIDATION_TRANSPORT_TYPE_WIFI,
+                /* duration= */ 1000);
+    }
+
+    @Test
+    public void testReportValidationMetricsAtom_NotValidated() {
+        ConnectivityDiagnosticsManager.ConnectivityDiagnosticsCallback callback =
+                mConnectivityDiagnosticsCallbackArgumentCaptor.getValue();
+        when(mMockNetworkCapabilities.hasCapability(
+                        eq(NetworkCapabilities.NET_CAPABILITY_VALIDATED)))
+                .thenReturn(true);
+        when(mMockNetworkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR))
+                .thenReturn(true);
+        IwlanCarrierConfig.putTestConfigIntArray(
+                IwlanCarrierConfig.KEY_UNDERLYING_NETWORK_VALIDATION_EVENTS_INT_ARRAY,
+                new int[] {
+                    IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_MAKING_CALL,
+                    IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_SCREEN_ON
+                });
+
+        advanceClockByTimeMs(100000);
+        mEpdgTunnelManager.validateUnderlyingNetwork(
+                IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_SCREEN_ON);
+        mTestLooper.dispatchAll();
+        verify(mMockConnectivityManager, times(1))
+                .reportNetworkConnectivity(eq(mMockDefaultNetwork), eq(false));
+
+        MetricsAtom metricsAtom = mEpdgTunnelManager.getValidationMetricsAtom(mMockDefaultNetwork);
+        advanceClockByTimeMs(1000);
+        callback.onConnectivityReportAvailable(
+                createConnectivityReport(
+                        mMockDefaultNetwork, ConnectivityReport.NETWORK_VALIDATION_RESULT_INVALID));
+
+        verifyValidationMetricsAtom(
+                metricsAtom,
+                NETWORK_VALIDATION_EVENT_SCREEN_ON,
+                NETWORK_VALIDATION_RESULT_INVALID,
+                NETWORK_VALIDATION_TRANSPORT_TYPE_CELLULAR,
+                /* duration= */ 1000);
+    }
+
+    @Test
+    public void testClose() {
+        ConnectivityDiagnosticsManager.ConnectivityDiagnosticsCallback callback =
+                mConnectivityDiagnosticsCallbackArgumentCaptor.getValue();
+        mEpdgTunnelManager.close();
+        verify(mMockConnectivityDiagnosticsManager, times(1))
+                .unregisterConnectivityDiagnosticsCallback(eq(callback));
+    }
 }
```

