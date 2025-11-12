```diff
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index ad058e7..c705f69 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -6,5 +6,5 @@ jsonlint = true
 xmllint = true
 
 [Hook Scripts]
-aosp_hook = ${REPO_ROOT}/frameworks/base/tools/aosp/aosp_sha.sh ${PREUPLOAD_COMMIT} "."
+#aosp_hook = ${REPO_ROOT}/frameworks/base/tools/aosp/aosp_sha.sh ${PREUPLOAD_COMMIT} "."
 checkstyle_hook = ${REPO_ROOT}/prebuilts/checkstyle/checkstyle.py --sha ${PREUPLOAD_COMMIT}
diff --git a/apex/Android.bp b/apex/Android.bp
index f465cca..1feb01c 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -40,4 +40,8 @@ apex {
     min_sdk_version: "33",
     apps: ["rkpdapp"],
     compile_multilib: "both",
+    licenses: [
+        "Android-Apache-2.0",
+        "opensourcerequest",
+    ],
 }
diff --git a/app/Android.bp b/app/Android.bp
index 132acf6..5d077d4 100644
--- a/app/Android.bp
+++ b/app/Android.bp
@@ -59,7 +59,7 @@ sdk {
 android_app {
     name: "rkpdapp",
     sdk_version: "module_current",
-    target_sdk_version: "35",
+    target_sdk_version: "36",
     min_sdk_version: "33",
     updatable: true,
     privileged: true,
@@ -79,6 +79,7 @@ android_app {
         "androidx.work_work-runtime",
         "cbor-java",
         "com.android.rkpdapp-aidl-java",
+        "rkpd_aconfig_flags_lib",
     ],
     resource_dirs: ["res"],
     srcs: [
diff --git a/app/AndroidManifest.xml b/app/AndroidManifest.xml
index b8ab08b..392a8ec 100644
--- a/app/AndroidManifest.xml
+++ b/app/AndroidManifest.xml
@@ -16,15 +16,25 @@
 
 <manifest xmlns:android="http://schemas.android.com/apk/res/android"
     package="com.android.rkpdapp">
+    <queries>
+        <package android:name="com.google.android.gms" />
+    </queries>
 
     <application
         android:label="@string/app_name">
         <receiver android:name=".BootReceiver"
             android:exported="false">
-            <intent-filter >
+            <intent-filter>
                 <action android:name="android.intent.action.BOOT_COMPLETED"/>
             </intent-filter>
         </receiver>
+        <receiver android:name=".PackageRemovalReceiver"
+                  android:exported="true">
+            <intent-filter>
+                <action android:name="android.intent.action.PACKAGE_FULLY_REMOVED" />
+                <data android:scheme="package" />
+            </intent-filter>
+        </receiver>
         <service android:name=".provisioner.PeriodicProvisioner"
             android:permission="android.permission.BIND_JOB_SERVICE"
             android:exported="false">
@@ -41,5 +51,7 @@
     <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
     <uses-permission android:name="android.permission.INTERNET" />
     <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
+    <uses-permission android:name="android.permission.INTERACT_ACROSS_USERS_FULL" />
+    <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" />
 
 </manifest>
diff --git a/app/TEST_MAPPING b/app/TEST_MAPPING
index c783dee..9be5f9b 100644
--- a/app/TEST_MAPPING
+++ b/app/TEST_MAPPING
@@ -13,22 +13,9 @@
     {
       "name": "RkpdAppGoogleIntegrationTests",
       "keywords": ["internal"]
-    }
-  ],
-  "avf-postsubmit": [
-    {
-      "name": "AvfRkpdAppGoogleIntegrationTests",
-      "keywords": ["internal"]
-    }
-  ],
-  "avf-presubmit": [
-    {
-      // TODO(b/325610326): Add this target to presubmit once there is enough
-      // SLO data for it.
-      "name": "AvfRkpdAppIntegrationTests"
     },
     {
-      "name": "AvfRkpdVmAttestationTestApp"
+      "name": "AvfRkpdAppIntegrationTests"
     }
   ],
   "mainline-presubmit": [
diff --git a/app/src/com/android/rkpdapp/PackageRemovalReceiver.java b/app/src/com/android/rkpdapp/PackageRemovalReceiver.java
new file mode 100644
index 0000000..5cf8959
--- /dev/null
+++ b/app/src/com/android/rkpdapp/PackageRemovalReceiver.java
@@ -0,0 +1,47 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.rkpdapp;
+
+import android.content.BroadcastReceiver;
+import android.content.Context;
+import android.content.Intent;
+import android.util.Log;
+
+import com.android.rkpdapp.database.ProvisionedKeyDao;
+import com.android.rkpdapp.database.RkpdDatabase;
+
+/**
+ * A receiver class that listens for package removed broadcast and removes the
+ * associated attestation key.
+ */
+public class PackageRemovalReceiver extends BroadcastReceiver {
+    private static final String TAG = "RkpdBroadcast";
+    private static final int KEYSTORE_SERVICE_UID = 1017;
+
+    @Override
+    public void onReceive(Context context, Intent intent) {
+        Log.i(TAG, "Caught package_removed intent, waking up.");
+        ThreadPool.EXECUTOR.execute(() -> processPackageRemovalIntent(context, intent));
+    }
+
+    private void processPackageRemovalIntent(Context context, Intent intent) {
+        ProvisionedKeyDao keyDao = RkpdDatabase.getDatabase(context).provisionedKeyDao();
+        int uid = intent.getExtras().getInt(Intent.EXTRA_UID);
+        keyDao.deleteAllKeysForClientAndKeyId(KEYSTORE_SERVICE_UID, uid);
+        Log.i(TAG, "Deleted associated keys for uid: " + uid);
+    }
+}
diff --git a/app/src/com/android/rkpdapp/database/ProvisionedKeyDao.java b/app/src/com/android/rkpdapp/database/ProvisionedKeyDao.java
index af18a25..d31ec9b 100644
--- a/app/src/com/android/rkpdapp/database/ProvisionedKeyDao.java
+++ b/app/src/com/android/rkpdapp/database/ProvisionedKeyDao.java
@@ -56,6 +56,13 @@ public abstract class ProvisionedKeyDao {
     @Query("DELETE from provisioned_keys WHERE key_blob = :keyBlob")
     public abstract void deleteKey(byte[] keyBlob);
 
+    /**
+     * Delete all the provisioned keys for a given key_id for keystore service.
+     * 1017 is the keystore service user id.
+     */
+    @Query("DELETE FROM provisioned_keys WHERE key_id = :keyId AND client_uid = :clientId")
+    public abstract void deleteAllKeysForClientAndKeyId(int clientId, int keyId);
+
     /**
      * Delete all the provisioned keys.
      */
diff --git a/app/src/com/android/rkpdapp/interfaces/ServerInterface.java b/app/src/com/android/rkpdapp/interfaces/ServerInterface.java
index 95f4dcf..393f450 100644
--- a/app/src/com/android/rkpdapp/interfaces/ServerInterface.java
+++ b/app/src/com/android/rkpdapp/interfaces/ServerInterface.java
@@ -17,7 +17,6 @@
 package com.android.rkpdapp.interfaces;
 
 import android.content.Context;
-import android.content.pm.PackageManager;
 import android.net.ConnectivityManager;
 import android.net.NetworkCapabilities;
 import android.net.TrafficStats;
@@ -32,6 +31,7 @@ import com.android.rkpdapp.GeekResponse;
 import com.android.rkpdapp.RkpdException;
 import com.android.rkpdapp.metrics.ProvisioningAttempt;
 import com.android.rkpdapp.utils.CborUtils;
+import com.android.rkpdapp.utils.NetworkUtils;
 import com.android.rkpdapp.utils.Settings;
 import com.android.rkpdapp.utils.StopWatch;
 import com.android.rkpdapp.utils.X509Utils;
@@ -68,10 +68,7 @@ public class ServerInterface {
     private static final String TAG = "RkpdServerInterface";
     private static final String GEEK_URL = ":fetchEekChain";
     private static final String CERTIFICATE_SIGNING_URL = ":signCertificates";
-    private static final String CHALLENGE_PARAMETER = "challenge";
     private static final String REQUEST_ID_PARAMETER = "request_id";
-    private static final String GMS_PACKAGE = "com.google.android.gms";
-    private static final String CHINA_GMS_FEATURE = "cn.google.services";
 
     private final Context mContext;
     private final boolean mIsAsync;
@@ -166,19 +163,15 @@ public class ServerInterface {
      * provisioning server contains the MAC'ed CSRs and encrypted bundle containing the MAC key and
      * the hardware unique public key.
      *
-     * @param csr The CBOR encoded data containing the relevant pieces needed for the server to
-     *                    sign the CSRs. The data encoded within comes from Keystore / KeyMint.
-     * @param challenge The challenge that was sent from the server. It is included here even though
-     *                    it is also included in `cborBlob` in order to allow the server to more
-     *                    easily reject bad requests.
+     * @param csr The CBOR encoded data containing the relevant pieces needed for the server to sign
+     *     the CSRs. The data encoded within comes from Keystore / KeyMint.
      * @return A List of byte arrays, where each array contains an entire DER-encoded certificate
-     *                    chain for one attestation key pair.
+     *     chain for one attestation key pair.
      */
-    public List<byte[]> requestSignedCertificates(byte[] csr, byte[] challenge,
-            ProvisioningAttempt metrics) throws RkpdException, InterruptedException {
+    public List<byte[]> requestSignedCertificates(byte[] csr, ProvisioningAttempt metrics)
+            throws RkpdException, InterruptedException {
         final byte[] cborBytes =
-                connectAndGetData(metrics, generateSignCertsUrl(challenge),
-                                  csr, Operation.SIGN_CERTS);
+                connectAndGetData(metrics, generateSignCertsUrl(), csr, Operation.SIGN_CERTS);
         List<byte[]> certChains = CborUtils.parseSignedCertificates(cborBytes);
         if (certChains == null) {
             metrics.setStatus(ProvisioningAttempt.Status.INTERNAL_ERROR);
@@ -203,17 +196,17 @@ public class ServerInterface {
         return certChains;
     }
 
-    private URL generateSignCertsUrl(byte[] challenge) throws RkpdException {
+    private URL generateSignCertsUrl() throws RkpdException {
         try {
-            return new URL(Uri.parse(Settings.getUrl(mContext)).buildUpon()
-                    .appendEncodedPath(CERTIFICATE_SIGNING_URL)
-                    .appendQueryParameter(CHALLENGE_PARAMETER,
-                            Base64.encodeToString(challenge, Base64.URL_SAFE | Base64.NO_WRAP))
-                    .appendQueryParameter(REQUEST_ID_PARAMETER, generateAndLogRequestId())
-                    .build()
-                    .toString()
-                    // Needed due to the `:` in the URL endpoint.
-                    .replaceFirst("%3A", ":"));
+            return new URL(
+                    Uri.parse(Settings.getUrl(mContext))
+                            .buildUpon()
+                            .appendEncodedPath(CERTIFICATE_SIGNING_URL)
+                            .appendQueryParameter(REQUEST_ID_PARAMETER, generateAndLogRequestId())
+                            .build()
+                            .toString()
+                            // Needed due to the `:` in the URL endpoint.
+                            .replaceFirst("%3A", ":"));
         } catch (MalformedURLException e) {
             throw new RkpdException(RkpdException.ErrorCode.HTTP_CLIENT_ERROR, "Bad URL", e);
         }
@@ -244,7 +237,7 @@ public class ServerInterface {
         }
         // Since fetchGeek would be the first call for any sort of provisioning, we are okay
         // checking network consent here.
-        if (!assumeNetworkConsent(mContext)) {
+        if (!NetworkUtils.assumeNetworkConsent(mContext)) {
             throw new RkpdException(RkpdException.ErrorCode.NETWORK_COMMUNICATION_ERROR,
                     "Network communication consent not provided. Need to enable GMSCore app.");
         }
@@ -361,29 +354,6 @@ public class ServerInterface {
         return new String(bytes, charset);
     }
 
-    /**
-     * Checks whether GMSCore is installed and enabled for restricted regions.
-     * This lets us assume that user has consented to connecting to Google
-     * servers to provide attestation service.
-     * For all other regions, we assume consent by default since this is an
-     * Android OS-level application.
-     *
-     * @return True if user consent can be assumed else false.
-     */
-    @VisibleForTesting
-    public static boolean assumeNetworkConsent(Context context) {
-        PackageManager pm = context.getPackageManager();
-        if (pm.hasSystemFeature(CHINA_GMS_FEATURE)) {
-            // For china GMS, we can simply check whether GMS package is installed and enabled.
-            try {
-                return pm.getApplicationInfo(GMS_PACKAGE, 0).enabled;
-            } catch (PackageManager.NameNotFoundException e) {
-                return false;
-            }
-        }
-        return true;
-    }
-
     private static Charset getCharsetFromContentTypeHeader(String contentType) {
         final String[] contentTypeParts = contentType.split(";");
         if (contentTypeParts.length != 2) {
diff --git a/app/src/com/android/rkpdapp/provisioner/Provisioner.java b/app/src/com/android/rkpdapp/provisioner/Provisioner.java
index 2119c0c..e407a34 100644
--- a/app/src/com/android/rkpdapp/provisioner/Provisioner.java
+++ b/app/src/com/android/rkpdapp/provisioner/Provisioner.java
@@ -19,7 +19,7 @@ package com.android.rkpdapp.provisioner;
 import android.content.Context;
 import android.os.RemoteException;
 import android.util.Log;
-
+import co.nstant.in.cbor.CborException;
 import com.android.rkpdapp.GeekResponse;
 import com.android.rkpdapp.RkpdException;
 import com.android.rkpdapp.database.InstantConverter;
@@ -32,7 +32,6 @@ import com.android.rkpdapp.metrics.ProvisioningAttempt;
 import com.android.rkpdapp.utils.Settings;
 import com.android.rkpdapp.utils.StatsProcessor;
 import com.android.rkpdapp.utils.X509Utils;
-
 import java.security.cert.X509Certificate;
 import java.time.Instant;
 import java.time.temporal.ChronoUnit;
@@ -40,8 +39,6 @@ import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.List;
 
-import co.nstant.in.cbor.CborException;
-
 /**
  * Provides an easy package to run the provisioning process from start to finish, interfacing
  * with the system interface and the server backend in order to provision attestation certificates
@@ -158,8 +155,8 @@ public class Provisioner {
             throw new RkpdException(RkpdException.ErrorCode.INTERNAL_ERROR,
                     "Failed to serialize payload");
         }
-        return new ServerInterface(mContext, mIsAsync).requestSignedCertificates(certRequest,
-                response.getChallenge(), metrics);
+        return new ServerInterface(mContext, mIsAsync)
+                .requestSignedCertificates(certRequest, metrics);
     }
 
     private List<ProvisionedKey> associateCertsWithKeys(List<byte[]> certChains,
diff --git a/app/src/com/android/rkpdapp/utils/NetworkUtils.java b/app/src/com/android/rkpdapp/utils/NetworkUtils.java
new file mode 100644
index 0000000..08036a5
--- /dev/null
+++ b/app/src/com/android/rkpdapp/utils/NetworkUtils.java
@@ -0,0 +1,55 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.rkpdapp.utils;
+
+import android.content.Context;
+import android.content.pm.PackageManager;
+import android.os.SystemProperties;
+
+import com.android.rkpd.flags.Flags;
+
+public class NetworkUtils {
+    private static final String GMS_PACKAGE = "com.google.android.gms";
+    private static final String CHINA_GMS_FEATURE = "cn.google.services";
+
+    /**
+     * Checks whether GMSCore is installed and enabled for restricted regions.
+     * This lets us assume that user has consented to connecting to Google
+     * servers to provide attestation service.
+     * For all other regions, we assume consent by default since this is an
+     * Android OS-level application.
+     *
+     * @return True if user consent can be assumed else false.
+     */
+    public static boolean assumeNetworkConsent(Context context) {
+        if (Flags.allowNetworkConsentBypass() && SystemProperties.getBoolean(
+                "remote_provisioning.skip_network_consent_check", false)) {
+            return true;
+        }
+
+        PackageManager pm = context.getPackageManager();
+        if (pm.hasSystemFeature(CHINA_GMS_FEATURE)) {
+            // For china GMS, we can simply check whether GMS package is installed and enabled.
+            try {
+                return pm.getApplicationInfo(GMS_PACKAGE, 0).enabled;
+            } catch (PackageManager.NameNotFoundException e) {
+                return false;
+            }
+        }
+        return true;
+    }
+}
diff --git a/app/tests/avf/Android.bp b/app/tests/avf/Android.bp
index 1d0cd37..6b17dc4 100644
--- a/app/tests/avf/Android.bp
+++ b/app/tests/avf/Android.bp
@@ -6,7 +6,7 @@ android_test {
     name: "AvfRkpdAppIntegrationTests",
     srcs: ["src/**/*.java"],
     static_libs: [
-        "MicrodroidDeviceTestHelper",
+        "MicrodroidDeviceTestLib",
         "Nene",
         "RkpdAppTestUtil",
         "androidx.test.ext.junit",
diff --git a/app/tests/avf/AndroidTest.xml b/app/tests/avf/AndroidTest.xml
index e57ca1d..5d89aef 100644
--- a/app/tests/avf/AndroidTest.xml
+++ b/app/tests/avf/AndroidTest.xml
@@ -18,6 +18,12 @@
     <option name="test-suite-tag" value="apct" />
     <option name="test-suite-tag" value="apct-instrumentation" />
 
+    <!-- Only run if the VM attestation is supported.
+         Match with MicrodroidDeviceTestBase#ensureVmAttestationSupported() -->
+    <object type="module_controller" class="com.android.tradefed.testtype.suite.module.ShippingApiLevelModuleController">
+        <option name="vsr-min-api-level" value="202504" />
+    </object>
+
     <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller">
         <option name="cleanup-apks" value="true" />
         <option name="test-file-name" value="AvfRkpdAppIntegrationTests.apk" />
diff --git a/app/tests/e2e/src/com/android/rkpdapp/e2etest/KeystoreIntegrationTest.java b/app/tests/e2e/src/com/android/rkpdapp/e2etest/KeystoreIntegrationTest.java
index 0d8a66f..42d33ee 100644
--- a/app/tests/e2e/src/com/android/rkpdapp/e2etest/KeystoreIntegrationTest.java
+++ b/app/tests/e2e/src/com/android/rkpdapp/e2etest/KeystoreIntegrationTest.java
@@ -33,6 +33,7 @@ import android.os.SystemProperties;
 import android.security.KeyStoreException;
 import android.security.keystore.KeyGenParameterSpec;
 import android.system.keystore2.ResponseCode;
+import android.util.Log;
 
 import androidx.test.core.app.ApplicationProvider;
 import androidx.work.ListenableWorker;
@@ -63,6 +64,8 @@ import org.junit.rules.TestName;
 import org.junit.runner.RunWith;
 import org.junit.runners.Parameterized;
 
+import java.net.InetAddress;
+import java.net.UnknownHostException;
 import java.security.KeyPairGenerator;
 import java.security.KeyStore;
 import java.security.ProviderException;
@@ -77,6 +80,7 @@ import java.util.concurrent.Executors;
 
 @RunWith(Parameterized.class)
 public class KeystoreIntegrationTest {
+    private static final String TAG = "KeystoreIntegrationTest";
     // This is the SEQUENCE header and AlgorithmIdentifier that prefix the raw public key. This
     // lets us create DER-encoded SubjectPublicKeyInfo by concatenating the prefix with the raw key
     // to produce the following:
@@ -130,6 +134,11 @@ public class KeystoreIntegrationTest {
                 .that(mInstanceName)
                 .isIn(List.of("default", "strongbox"));
 
+        assume()
+                .withMessage("Device is not able to resolve hostnames. Check network connection.")
+                .that(isDnsResolutionSuccessful())
+                .isTrue();
+
         Settings.clearPreferences(sContext);
 
         mPeriodicProvisionerLock = PeriodicProvisioner.lock();
@@ -451,4 +460,21 @@ public class KeystoreIntegrationTest {
                 throw new IllegalArgumentException("Unexpected instance: " + mInstanceName);
         }
     }
+
+    private boolean isDnsResolutionSuccessful() {
+        String hostname = SystemProperties.get("remote_provisioning.hostname");
+        try {
+            InetAddress ignored = InetAddress.getByName(hostname);
+            // If the inet address is resolving to null address, we should let
+            // it continue to test and make noise since this is an unknown
+            // failure.
+            return true;
+        } catch (Exception e) {
+            Log.e(TAG, "Exception encountered during test setup.", e);
+            // UnknownHostException signals the DNS resolution failure.
+            // Anything else would be unknown, and we should allow our testing
+            // to make noise in that case.
+            return !(e instanceof UnknownHostException);
+        }
+    }
 }
diff --git a/app/tests/unit/Android.bp b/app/tests/unit/Android.bp
index 2a9ae30..c4f9897 100644
--- a/app/tests/unit/Android.bp
+++ b/app/tests/unit/Android.bp
@@ -33,6 +33,8 @@ android_test {
         "truth",
         "rkpdapp-tink-prebuilt-test-only",
         "bouncycastle-unbundled",
+        "flag-junit",
+        "rkpd_aconfig_flags_lib",
     ],
     platform_apis: true,
     test_suites: [
diff --git a/app/tests/unit/src/com/android/rkpdapp/unittest/NetworkUtilsTest.java b/app/tests/unit/src/com/android/rkpdapp/unittest/NetworkUtilsTest.java
new file mode 100644
index 0000000..ea28fbd
--- /dev/null
+++ b/app/tests/unit/src/com/android/rkpdapp/unittest/NetworkUtilsTest.java
@@ -0,0 +1,113 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.rkpdapp.unittest;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import android.content.Context;
+import android.content.pm.ApplicationInfo;
+import android.content.pm.PackageManager;
+import android.platform.test.annotations.RequiresFlagsDisabled;
+import android.platform.test.annotations.RequiresFlagsEnabled;
+import android.platform.test.flag.junit.CheckFlagsRule;
+import android.platform.test.flag.junit.DeviceFlagsValueProvider;
+
+import com.android.rkpd.flags.Flags;
+import com.android.rkpdapp.testutil.SystemPropertySetter;
+import com.android.rkpdapp.utils.NetworkUtils;
+
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+import org.mockito.Mockito;
+
+@RunWith(JUnit4.class)
+public class NetworkUtilsTest {
+    @Rule
+    public final CheckFlagsRule mCheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule();
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_ALLOW_NETWORK_CONSENT_BYPASS)
+    public void testConnectionConsent() throws Exception {
+        String cnGmsFeature = "cn.google.services";
+        PackageManager mockedPackageManager = Mockito.mock(PackageManager.class);
+        Context mockedContext = Mockito.mock(Context.class);
+        ApplicationInfo fakeApplicationInfo = new ApplicationInfo();
+
+        Mockito.when(mockedContext.getPackageManager()).thenReturn(mockedPackageManager);
+        Mockito.when(mockedPackageManager.hasSystemFeature(cnGmsFeature)).thenReturn(true);
+        Mockito.when(mockedPackageManager.getApplicationInfo(Mockito.any(), Mockito.eq(0)))
+                .thenReturn(fakeApplicationInfo);
+
+        try (SystemPropertySetter check = SystemPropertySetter.setSkipNetworkConsentCheck(true)) {
+            if (check != null) {
+                fakeApplicationInfo.enabled = false;
+                assertThat(NetworkUtils.assumeNetworkConsent(mockedContext)).isTrue();
+            }
+        }
+
+        try (SystemPropertySetter ignored =
+                     SystemPropertySetter.setSkipNetworkConsentCheck(false)) {
+            fakeApplicationInfo.enabled = false;
+            assertThat(NetworkUtils.assumeNetworkConsent(mockedContext)).isFalse();
+
+            fakeApplicationInfo.enabled = true;
+            assertThat(NetworkUtils.assumeNetworkConsent(mockedContext)).isTrue();
+
+            Mockito.when(mockedPackageManager.getApplicationInfo(Mockito.any(), Mockito.eq(0)))
+                    .thenThrow(new PackageManager.NameNotFoundException());
+            assertThat(NetworkUtils.assumeNetworkConsent(mockedContext)).isFalse();
+
+            Mockito.when(mockedPackageManager.hasSystemFeature(cnGmsFeature)).thenReturn(false);
+            assertThat(NetworkUtils.assumeNetworkConsent(mockedContext)).isTrue();
+
+            fakeApplicationInfo.enabled = false;
+            assertThat(NetworkUtils.assumeNetworkConsent(mockedContext)).isTrue();
+        }
+    }
+
+    @Test
+    @RequiresFlagsDisabled(Flags.FLAG_ALLOW_NETWORK_CONSENT_BYPASS)
+    public void testConnectionConsentFlagDisabled() throws Exception {
+        String cnGmsFeature = "cn.google.services";
+        PackageManager mockedPackageManager = Mockito.mock(PackageManager.class);
+        Context mockedContext = Mockito.mock(Context.class);
+        ApplicationInfo fakeApplicationInfo = new ApplicationInfo();
+
+        Mockito.when(mockedContext.getPackageManager()).thenReturn(mockedPackageManager);
+        Mockito.when(mockedPackageManager.hasSystemFeature(cnGmsFeature)).thenReturn(true);
+        Mockito.when(mockedPackageManager.getApplicationInfo(Mockito.any(), Mockito.eq(0)))
+                .thenReturn(fakeApplicationInfo);
+
+        fakeApplicationInfo.enabled = false;
+        assertThat(NetworkUtils.assumeNetworkConsent(mockedContext)).isFalse();
+
+        fakeApplicationInfo.enabled = true;
+        assertThat(NetworkUtils.assumeNetworkConsent(mockedContext)).isTrue();
+
+        Mockito.when(mockedPackageManager.getApplicationInfo(Mockito.any(), Mockito.eq(0)))
+                .thenThrow(new PackageManager.NameNotFoundException());
+        assertThat(NetworkUtils.assumeNetworkConsent(mockedContext)).isFalse();
+
+        Mockito.when(mockedPackageManager.hasSystemFeature(cnGmsFeature)).thenReturn(false);
+        assertThat(NetworkUtils.assumeNetworkConsent(mockedContext)).isTrue();
+
+        fakeApplicationInfo.enabled = false;
+        assertThat(NetworkUtils.assumeNetworkConsent(mockedContext)).isTrue();
+    }
+}
diff --git a/app/tests/unit/src/com/android/rkpdapp/unittest/RkpdDatabaseTest.java b/app/tests/unit/src/com/android/rkpdapp/unittest/RkpdDatabaseTest.java
index a21deb5..9dd451a 100644
--- a/app/tests/unit/src/com/android/rkpdapp/unittest/RkpdDatabaseTest.java
+++ b/app/tests/unit/src/com/android/rkpdapp/unittest/RkpdDatabaseTest.java
@@ -54,6 +54,7 @@ public class RkpdDatabaseTest {
     private static final Instant TEST_KEY_EXPIRY = Instant.now().plus(Duration.ofHours(1));
     private static final int FAKE_CLIENT_UID = 1;
     private static final int FAKE_CLIENT_UID_2 = 2;
+    private static final int KEYSTORE_CLIENT_UID = 1017;
     private static final int FAKE_KEY_ID = 1;
     private static final int FAKE_CLIENT_UID_3 = 3;
     private static final int FAKE_KEY_ID_2 = 2;
@@ -184,6 +185,36 @@ public class RkpdDatabaseTest {
         assertThat(key.keyBlob).isEqualTo(mProvisionedKey2.keyBlob);
     }
 
+    /* TODO: Uncomment this test once the code is out in the wild to prevent API not available
+     * failures.
+     */
+    /*
+    @Test
+    public void testDeleteSingleUidKey() {
+        ProvisionedKey key3 = new ProvisionedKey(TEST_KEY_BLOB_3, TEST_HAL_2, TEST_KEY_BLOB_3,
+                TEST_KEY_BLOB_3, TEST_KEY_EXPIRY);
+
+        mKeyDao.insertKeys(List.of(mProvisionedKey1, mProvisionedKey2, key3));
+        List<ProvisionedKey> keysInDatabase = mKeyDao.getAllKeys();
+        assertThat(keysInDatabase).hasSize(3);
+
+        assertThat(mKeyDao.getOrAssignKey(TEST_HAL_1, Instant.now(), KEYSTORE_CLIENT_UID,
+                FAKE_KEY_ID)).isNotNull();
+        assertThat(mKeyDao.getOrAssignKey(TEST_HAL_2, Instant.now(), KEYSTORE_CLIENT_UID,
+                FAKE_KEY_ID_2)).isNotNull();
+        assertThat(mKeyDao.getOrAssignKey(TEST_HAL_2, Instant.now(), FAKE_CLIENT_UID,
+                FAKE_KEY_ID)).isNotNull();
+
+        mKeyDao.deleteAllKeysForClientAndKeyId(KEYSTORE_CLIENT_UID, FAKE_KEY_ID);
+        keysInDatabase = mKeyDao.getAllKeys();
+        assertThat(keysInDatabase).hasSize(2);
+        assertThat(keysInDatabase.get(0).keyId).isEqualTo(FAKE_KEY_ID_2);
+
+        mKeyDao.deleteAllKeysForClientAndKeyId(KEYSTORE_CLIENT_UID, FAKE_KEY_ID_2);
+        keysInDatabase = mKeyDao.getAllKeys();
+        assertThat(keysInDatabase).hasSize(1);
+    }*/
+
     @Test
     public void testGetTotalExpiringKeysForIrpc() {
         final Instant past = Instant.now().minus(1000, ChronoUnit.MINUTES);
diff --git a/app/tests/unit/src/com/android/rkpdapp/unittest/ServerInterfaceTest.java b/app/tests/unit/src/com/android/rkpdapp/unittest/ServerInterfaceTest.java
index 12ab92d..548f9ea 100644
--- a/app/tests/unit/src/com/android/rkpdapp/unittest/ServerInterfaceTest.java
+++ b/app/tests/unit/src/com/android/rkpdapp/unittest/ServerInterfaceTest.java
@@ -20,8 +20,6 @@ import static com.google.common.truth.Truth.assertThat;
 import static com.google.common.truth.Truth.assertWithMessage;
 
 import android.content.Context;
-import android.content.pm.ApplicationInfo;
-import android.content.pm.PackageManager;
 import android.util.Base64;
 
 import androidx.test.core.app.ApplicationProvider;
@@ -171,7 +169,7 @@ public class ServerInterfaceTest {
                     TIME_TO_REFRESH_HOURS /* expiringBy */, server.getUrl());
             ProvisioningAttempt metrics = ProvisioningAttempt.createScheduledAttemptMetrics(
                     sContext);
-            mServerInterface.requestSignedCertificates(new byte[0], new byte[0], metrics);
+            mServerInterface.requestSignedCertificates(new byte[0], metrics);
             assertWithMessage("Should fail due to unregistered device.").fail();
         } catch (RkpdException e) {
             assertThat(e.getErrorCode()).isEqualTo(RkpdException.ErrorCode.DEVICE_NOT_REGISTERED);
@@ -188,7 +186,7 @@ public class ServerInterfaceTest {
             Settings.setMaxRequestTime(sContext, 100);
             ProvisioningAttempt metrics = ProvisioningAttempt.createScheduledAttemptMetrics(
                     sContext);
-            mServerInterface.requestSignedCertificates(new byte[0], new byte[0], metrics);
+            mServerInterface.requestSignedCertificates(new byte[0], metrics);
             assertWithMessage("Should fail due to client error.").fail();
         } catch (RkpdException e) {
             assertThat(e.getErrorCode()).isEqualTo(RkpdException.ErrorCode.HTTP_CLIENT_ERROR);
@@ -204,7 +202,7 @@ public class ServerInterfaceTest {
                     TIME_TO_REFRESH_HOURS /* expiringBy */, server.getUrl());
             ProvisioningAttempt metrics = ProvisioningAttempt.createScheduledAttemptMetrics(
                     sContext);
-            mServerInterface.requestSignedCertificates(new byte[0], new byte[0], metrics);
+            mServerInterface.requestSignedCertificates(new byte[0], metrics);
             assertWithMessage("Should fail due to invalid cbor.").fail();
         } catch (RkpdException e) {
             assertThat(e.getErrorCode()).isEqualTo(RkpdException.ErrorCode.INTERNAL_ERROR);
@@ -221,8 +219,8 @@ public class ServerInterfaceTest {
                     TIME_TO_REFRESH_HOURS /* expiringBy */, server.getUrl());
             ProvisioningAttempt metrics = ProvisioningAttempt.createScheduledAttemptMetrics(
                     sContext);
-            List<byte[]> certChains = mServerInterface.requestSignedCertificates(new byte[0],
-                    new byte[0], metrics);
+            List<byte[]> certChains =
+                    mServerInterface.requestSignedCertificates(new byte[0], metrics);
             assertThat(certChains).isEmpty();
             assertThat(certChains).isNotNull();
         }
@@ -407,33 +405,4 @@ public class ServerInterfaceTest {
         assertThat(serverInterface.getConnectTimeoutMs()).isEqualTo(
                 ServerInterface.SYNC_CONNECT_TIMEOUT_OPEN_MS);
     }
-
-    @Test
-    public void testConnectionConsent() throws Exception {
-        String cnGmsFeature = "cn.google.services";
-        PackageManager mockedPackageManager = Mockito.mock(PackageManager.class);
-        Context mockedContext = Mockito.mock(Context.class);
-        ApplicationInfo fakeApplicationInfo = new ApplicationInfo();
-
-        Mockito.when(mockedContext.getPackageManager()).thenReturn(mockedPackageManager);
-        Mockito.when(mockedPackageManager.hasSystemFeature(cnGmsFeature)).thenReturn(true);
-        Mockito.when(mockedPackageManager.getApplicationInfo(Mockito.any(), Mockito.eq(0)))
-                .thenReturn(fakeApplicationInfo);
-
-        fakeApplicationInfo.enabled = false;
-        assertThat(ServerInterface.assumeNetworkConsent(mockedContext)).isFalse();
-
-        fakeApplicationInfo.enabled = true;
-        assertThat(ServerInterface.assumeNetworkConsent(mockedContext)).isTrue();
-
-        Mockito.when(mockedPackageManager.getApplicationInfo(Mockito.any(), Mockito.eq(0)))
-                .thenThrow(new PackageManager.NameNotFoundException());
-        assertThat(ServerInterface.assumeNetworkConsent(mockedContext)).isFalse();
-
-        Mockito.when(mockedPackageManager.hasSystemFeature(cnGmsFeature)).thenReturn(false);
-        assertThat(ServerInterface.assumeNetworkConsent(mockedContext)).isTrue();
-
-        fakeApplicationInfo.enabled = false;
-        assertThat(ServerInterface.assumeNetworkConsent(mockedContext)).isTrue();
-    }
 }
diff --git a/app/tests/util/src/com/android/rkpdapp/testutil/SystemPropertySetter.java b/app/tests/util/src/com/android/rkpdapp/testutil/SystemPropertySetter.java
index 70b404c..888a7ad 100644
--- a/app/tests/util/src/com/android/rkpdapp/testutil/SystemPropertySetter.java
+++ b/app/tests/util/src/com/android/rkpdapp/testutil/SystemPropertySetter.java
@@ -37,6 +37,19 @@ public class SystemPropertySetter implements AutoCloseable {
         }
     }
 
+    /**
+     * Sets the system property to skip network consent checks.
+     * @param skipNetworkConsent boolean
+     * @return an instance of SystemPropertySetter.
+     */
+    public static SystemPropertySetter setSkipNetworkConsentCheck(boolean skipNetworkConsent) {
+        if (SystemProperties.get("remote_provisioning.skip_network_consent_check").isEmpty()) {
+            return null;
+        }
+        return new SystemPropertySetter("remote_provisioning.skip_network_consent_check",
+                String.valueOf(skipNetworkConsent));
+    }
+
     private SystemPropertySetter(String key, String value) {
         mKey = key;
         mOriginalValue = SystemProperties.get(key, "");
@@ -46,4 +59,4 @@ public class SystemPropertySetter implements AutoCloseable {
     public void close() {
         SystemProperties.set(mKey, mOriginalValue);
     }
-}
+}
\ No newline at end of file
diff --git a/flags/Android.bp b/flags/Android.bp
new file mode 100644
index 0000000..6a473d4
--- /dev/null
+++ b/flags/Android.bp
@@ -0,0 +1,39 @@
+//
+// Copyright (C) 2025 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+//
+
+package {
+    default_team: "trendy_team_android_hardware_backed_security",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+aconfig_declarations {
+    name: "rkpd_aconfig_flags",
+    package: "com.android.rkpd.flags",
+    container: "com.android.rkpd",
+    srcs: ["rkpd_flags.aconfig"],
+}
+
+java_aconfig_library {
+    name: "rkpd_aconfig_flags_lib",
+    aconfig_declarations: "rkpd_aconfig_flags",
+    min_sdk_version: "33",
+    apex_available: [
+        "com.android.rkpd",
+    ],
+    visibility: [
+        "//packages/modules/RemoteKeyProvisioning:__subpackages__",
+    ],
+}
diff --git a/flags/rkpd_flags.aconfig b/flags/rkpd_flags.aconfig
new file mode 100644
index 0000000..226e4c9
--- /dev/null
+++ b/flags/rkpd_flags.aconfig
@@ -0,0 +1,21 @@
+package: "com.android.rkpd.flags"
+container: "com.android.rkpd"
+
+##### Use the below as example.
+#flag {
+#    name: "test_flag"
+#    namespace: "hardware_backed_security"
+#    description: "This flag is a test flag. Create other flags based on this."
+#    bug: "bug number"
+#    metadata {
+#        # purpose can be either FEATURE or BUGFIX, else don't add metadata.
+#        purpose: PURPOSE_BUGFIX
+#    }
+#}
+
+flag {
+    name: "allow_network_consent_bypass"
+    namespace: "hardware_backed_security"
+    description: "When enabled, a system property may be set to indicate network access consent."
+    bug: "411197466"
+}
\ No newline at end of file
```

