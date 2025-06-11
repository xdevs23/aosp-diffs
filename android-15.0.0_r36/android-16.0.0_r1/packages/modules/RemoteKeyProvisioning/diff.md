```diff
diff --git a/app/Android.bp b/app/Android.bp
index 40f7f75..132acf6 100644
--- a/app/Android.bp
+++ b/app/Android.bp
@@ -59,7 +59,7 @@ sdk {
 android_app {
     name: "rkpdapp",
     sdk_version: "module_current",
-    target_sdk_version: "34",
+    target_sdk_version: "35",
     min_sdk_version: "33",
     updatable: true,
     privileged: true,
diff --git a/app/src/com/android/rkpdapp/provisioner/WidevineProvisioner.java b/app/src/com/android/rkpdapp/provisioner/WidevineProvisioner.java
index 7adfd4d..413377c 100644
--- a/app/src/com/android/rkpdapp/provisioner/WidevineProvisioner.java
+++ b/app/src/com/android/rkpdapp/provisioner/WidevineProvisioner.java
@@ -22,17 +22,14 @@ import android.media.MediaDrm;
 import android.media.UnsupportedSchemeException;
 import android.os.Build;
 import android.util.Log;
-
 import androidx.annotation.NonNull;
 import androidx.work.Worker;
 import androidx.work.WorkerParameters;
-
 import java.io.BufferedInputStream;
 import java.io.ByteArrayOutputStream;
 import java.io.IOException;
 import java.io.OutputStream;
 import java.net.HttpURLConnection;
-import java.net.SocketTimeoutException;
 import java.net.URL;
 import java.util.ArrayList;
 import java.util.HashMap;
@@ -165,17 +162,7 @@ public class WidevineProvisioner extends Worker {
                 "%s&signedRequest=%s",
                 req.getDefaultUrl(),
                 new String(data));
-        try {
-            return sendNetworkRequest(signedUrl);
-        } catch (SocketTimeoutException e) {
-            Log.i(TAG, "Provisioning failed with normal URL, retrying with China URL.");
-            final String chinaUrl = req.getDefaultUrl().replace(".com", ".cn");
-            final String signedUrlChina = String.format(
-                    "%s&signedRequest=%s",
-                    chinaUrl,
-                    new String(data));
-            return sendNetworkRequest(signedUrlChina);
-        }
+        return sendNetworkRequest(signedUrl);
     }
 
     private byte[] sendNetworkRequest(String url) throws IOException {
diff --git a/app/src/com/android/rkpdapp/utils/CborUtils.java b/app/src/com/android/rkpdapp/utils/CborUtils.java
index 2eee6d6..3c9b20a 100644
--- a/app/src/com/android/rkpdapp/utils/CborUtils.java
+++ b/app/src/com/android/rkpdapp/utils/CborUtils.java
@@ -16,7 +16,10 @@
 
 package com.android.rkpdapp.utils;
 
+import static android.content.pm.PackageManager.MATCH_APEX;
+
 import android.content.Context;
+import android.content.pm.PackageManager;
 import android.hardware.security.keymint.MacedPublicKey;
 import android.os.Build;
 import android.util.Log;
@@ -270,7 +273,7 @@ public class CborUtils {
      * device configuration values to return. In general, this boils down to if remote provisioning
      * is turned on at all or not.
      *
-     * @return the CBOR encoded provisioning information relevant to the server.
+     * @return the CBOR encoded provisioning information relevant to th.
      */
     public static byte[] buildProvisioningInfo(Context context) {
         try {
@@ -278,8 +281,8 @@ public class CborUtils {
             new CborEncoder(baos).encode(new CborBuilder()
                     .addMap()
                         .put("fingerprint", Build.FINGERPRINT)
-                        .put(new UnicodeString("id"),
-                             new UnsignedInteger(Settings.getId(context)))
+                        .put("id", Settings.getId(context))
+                        .put("version", getPackageVersion(context))
                         .end()
                     .build());
             return baos.toByteArray();
@@ -289,6 +292,19 @@ public class CborUtils {
         }
     }
 
+    private static long getPackageVersion(Context context) {
+        String packageName = context.getPackageName();
+        try {
+            return context
+                .getPackageManager()
+                .getPackageInfo(packageName, MATCH_APEX)
+                .getLongVersionCode();
+        } catch (PackageManager.NameNotFoundException e) {
+            Log.e(TAG, "Error looking up package " + packageName, e);
+            return 0;
+        }
+    }
+
     /**
      * Takes the various fields fetched from the server and the remote provisioning service and
      * formats them in the CBOR blob the server is expecting as defined by the
diff --git a/app/tests/e2e/AndroidTest.xml b/app/tests/e2e/AndroidTest.xml
index cda5eb0..ddf02e2 100644
--- a/app/tests/e2e/AndroidTest.xml
+++ b/app/tests/e2e/AndroidTest.xml
@@ -22,6 +22,8 @@
         <option name="test-file-name" value="RkpdAppIntegrationTests.apk" />
     </target_preparer>
 
+    <target_preparer class="com.android.tradefed.targetprep.RunOnSystemUserTargetPreparer"/>
+
     <test class="com.android.tradefed.testtype.AndroidJUnitTest" >
         <option name="package" value="com.android.rkpdapp.e2etest" />
         <option name="runner" value="androidx.test.runner.AndroidJUnitRunner" />
diff --git a/app/tests/unit/src/com/android/rkpdapp/unittest/CborUtilsTest.java b/app/tests/unit/src/com/android/rkpdapp/unittest/CborUtilsTest.java
index ae1ffcc..c166dd8 100644
--- a/app/tests/unit/src/com/android/rkpdapp/unittest/CborUtilsTest.java
+++ b/app/tests/unit/src/com/android/rkpdapp/unittest/CborUtilsTest.java
@@ -21,13 +21,16 @@ import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
 
+import android.content.Context;
 import android.os.Build;
 import android.platform.test.annotations.Presubmit;
 
+import androidx.test.core.app.ApplicationProvider;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 
 import com.android.rkpdapp.GeekResponse;
 import com.android.rkpdapp.utils.CborUtils;
+import com.android.rkpdapp.utils.Settings;
 
 import org.junit.Before;
 import org.junit.Test;
@@ -43,6 +46,7 @@ import java.util.List;
 import co.nstant.in.cbor.CborBuilder;
 import co.nstant.in.cbor.CborDecoder;
 import co.nstant.in.cbor.CborEncoder;
+import co.nstant.in.cbor.CborException;
 import co.nstant.in.cbor.model.Array;
 import co.nstant.in.cbor.model.ByteString;
 import co.nstant.in.cbor.model.DataItem;
@@ -459,4 +463,23 @@ public class CborUtilsTest {
         assertEquals(MajorType.UNICODE_STRING, fingerprint.getMajorType());
         assertEquals(Build.FINGERPRINT, fingerprint.toString());
     }
+
+    @Test
+    public void testBuildProvisioningInfo() throws CborException {
+        Context context = ApplicationProvider.getApplicationContext();
+
+        byte[] cbor = CborUtils.buildProvisioningInfo(context);
+        DataItem info = new CborDecoder(new ByteArrayInputStream(cbor)).decode().get(0);
+
+        assertEquals(
+                info,
+                new CborBuilder()
+                    .addMap()
+                        .put("fingerprint", Build.FINGERPRINT)
+                        .put("id", Settings.getId(context))
+                        .put("version", context.getApplicationInfo().compileSdkVersion)
+                        .end()
+                    .build()
+                    .get(0));
+    }
 }
```

