```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 490f0cb..0112b0e 100755
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -12,6 +12,7 @@
     <application android:label="@string/app_name"
             android:allowBackup="false"
             android:usesCleartextTraffic="false"
+            android:enableOnBackInvokedCallback="false"
             android:theme="@android:style/Theme.DeviceDefault.DayNight">
         <service android:name="com.android.keychain.KeyChainService"
             android:exported="true">
diff --git a/OWNERS b/OWNERS
index 7218804..6ae5ef6 100644
--- a/OWNERS
+++ b/OWNERS
@@ -7,9 +7,7 @@ rubinxu@google.com
 sandness@google.com
 
 # KeyStore / Keymaster owners
-jdanis@google.com
 swillden@google.com
 
 # Emeritus owners
-rgl@google.com
 eranm@google.com
diff --git a/robotests/Android.bp b/robotests/Android.bp
index 6a0678f..2f79d84 100644
--- a/robotests/Android.bp
+++ b/robotests/Android.bp
@@ -16,7 +16,5 @@ android_robolectric_test {
 
     instrumentation_for: "KeyChain",
 
-    upstream: true,
-
     strict_mode: false,
 }
diff --git a/src/com/android/keychain/KeyChainService.java b/src/com/android/keychain/KeyChainService.java
index 699f507..3edf94c 100644
--- a/src/com/android/keychain/KeyChainService.java
+++ b/src/com/android/keychain/KeyChainService.java
@@ -509,8 +509,8 @@ public class KeyChainService extends IntentService {
          *            {@code android.security.keystore.KeyProperties.UID_SELF} to indicate
          *            installation into the current user's system Keystore instance, or {@code
          *            Process.WIFI_UID} to indicate installation into the main user's WiFi Keystore
-         *            instance. It is only valid to pass {@code Process.WIFI_UID} to the KeyChain
-         *            service on user 0.
+         *            instance. Only admin users are allowed to pass {@code Process.WIFI_UID} to
+         *            the KeyChain service.
          * @return Whether the operation succeeded or not.
          */
         @Override public boolean installKeyPair(@Nullable byte[] privateKey,
diff --git a/support/src/com/android/keychain/tests/support/KeyChainServiceTestSupport.java b/support/src/com/android/keychain/tests/support/KeyChainServiceTestSupport.java
index 23e905c..27603e8 100644
--- a/support/src/com/android/keychain/tests/support/KeyChainServiceTestSupport.java
+++ b/support/src/com/android/keychain/tests/support/KeyChainServiceTestSupport.java
@@ -20,6 +20,7 @@ import android.app.Service;
 import android.content.Intent;
 import android.os.IBinder;
 import android.os.RemoteException;
+import android.os.UserHandle;
 import android.security.IKeyChainService;
 import android.security.KeyChain;
 import android.security.keystore.KeyProperties;
@@ -113,8 +114,9 @@ public class KeyChainServiceTestSupport extends Service {
     }
 
     private <T> T performBlockingKeyChainCall(KeyChainAction<T> action) throws RemoteException {
-        try (KeyChain.KeyChainConnection connection =
-        KeyChain.bind(KeyChainServiceTestSupport.this)) {
+        try (KeyChain.KeyChainConnection connection = KeyChain.bindAsUser(
+                KeyChainServiceTestSupport.this,
+                UserHandle.of(UserHandle.getCallingUserId()))) {
             return action.run(connection.getService());
         } catch (InterruptedException e) {
             // should never happen.
```

